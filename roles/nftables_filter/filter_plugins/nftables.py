#!/usr/bin/env python3

import re
import socket

REGEX_IPV4 = re.compile("^([0-9]{1,3}\\.){3}[0-9]{1,3}(\\/([0-9]|[1-2][0-9]|3[0-2]))?$")

class FilterModule(object):
  def resolve_negation(self, value: str) -> tuple[str, str]:
    negation_prefix = ""
    resolved_value = value

    if value.startswith("!"):
      # value negated
      negation_prefix = "!= "
      resolved_value = value[1:]

    return (negation_prefix, resolved_value)
  
  def resolve_dns(self, value: str) -> str:
    try:
      return socket.gethostbyname_ex(value)[2]
    except:
      raise Exception(f"could not resolve DNS name {value}")
  
  def resolve_host(self, value: str, host_aliases: list) -> str|list:
    # we only need to resolve when it's not an ip already
    if not REGEX_IPV4.match(value):
      # check if an alias with that name exists
      alias = list(filter(lambda a: a["name"] == value, host_aliases))

      if len (alias) == 0:
        # alias unknown, try to resolve dns
        return self.resolve_dns(value)
      else:
        # resolve
        return alias[0]["value"]
    
    return value

  def resolve_host_aliases(self, rule: dict, host_aliases: list) -> dict:
    # interate all fields that could have host aliases
    for field in ["src"]:
      if field in rule:
        # resolve negation
        (negation_operator, value) = self.resolve_negation(rule[field])

        if isinstance(value, list):
          # list of hosts
          resolved_value = []
          for h in rule[field]:
            resolved_value.append(self.resolve_host(h))

          rule[field] = f"{negation_operator}{{ { ', '.join(resolved_value) } }}"
        else:
          # single host
          resolved = self.resolve_host(value, host_aliases)
          if isinstance(resolved, list):
            rule[field] = f"{negation_operator}{{ { ', '.join(resolved) } }}"
          else:
            rule[field] = f"{negation_operator}{ resolved }"


    return rule
  
  def resolve_service_aliases(self, rule: dict, service_aliases: list) -> dict:
    # get alias by name
    alias = list(filter(lambda a: a["name"] == rule["service"], service_aliases))

    if len (alias) != 1:
      raise Exception(f"service alias {rule['service']} is unknown")
    
    alias = alias[0]
    
    # set rule proto
    rule["proto"] = alias["proto"]

    # check if list was supplied or just a single port
    if isinstance(alias["dport"], list) and len(alias["dport"]) > 1:
      # list of ports -> create anonymous set
      rule["dport"] = f"{{ { ', '.join(str(x) for x in alias['dport']) } }}"
    else:
      # single port
      if isinstance(alias["dport"], list):
        rule["dport"] = alias["dport"][0]
      else:
        rule["dport"] = alias["dport"]

    return rule

  def nft_rule(self, rule: dict) -> str:
    components = []

    # src
    if "src" in rule:
      # resolve negation
      components.append(f"ip saddr { rule['src'] }")

    # proto
    if "proto" in rule:
      components.append(rule['proto'])

    # destination port
    if "dport" in rule:
      components.append(f"dport { rule['dport'] }")

    if "log" in rule and rule["log"]:
      components.append(f"log prefix \"C={ rule['comment'] } \"")

    # counter
    components.append("counter")

    # policy, default accept
    if "policy" in rule:
      components.append(rule["policy"])
    else:
      components.append("accept")

    # comment
    components.append(f"comment \"{ rule['comment'] }\"")

    return " ".join(components)

  def nft_resolve(self, rule: dict, host_aliases: list, service_aliases: list) -> dict:
    resolved_rule = self.resolve_host_aliases(rule, host_aliases)

    if "service" in rule:
      resolved_rule = self.resolve_service_aliases(resolved_rule, service_aliases)

    return resolved_rule

  def filters(self):
    return {
        'nft_rule': self.nft_rule,
        'nft_resolve': self.nft_resolve
    }
