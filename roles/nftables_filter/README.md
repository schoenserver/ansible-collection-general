# nftables_filter

Add filtering rules to local nftables firewall.

## Variables

| Name                            | Default Value | Description                                              |
|---------------------------------|---------------|----------------------------------------------------------|
| **nftables_filter_name**        |               | Name of the filtering configuration                      |
| **nftables_filter_rules**       | `[]`          | List of filter rules                                     |
| nftables_filter_direction       | `input`       | Type of filter rules to add. Can be `input` or `forward` |
| nftables_filter_host_aliases    | `[]`          | List of host aliases that can be used in filter rules    |
| nftables_filter_service_aliases | `[]`          | List of service aliases that can be used in filter rules |
| nftables_filter_skip_validation | `false`       | Skip validation of role input variables                  |
