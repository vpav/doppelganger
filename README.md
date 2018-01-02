# doppelgänger - A tool to search for IDN lookalike/fake domains

doppelgänger is a tool that creates permutations of domain names using lookalike unicode characters and identifies registered domains using dns queries. 
It can be used to identify phishing domains.

# Example

* original: example.com
* eẋample.com (xn--eample-i77b.com)
* exampĺe.com (xn--exampe-mcb.com)
* exạmple.com (xn--exmple-xc8b.com)
* exampǀe.com (xn--exampe-f3b.com)
* exaṃple.com (xn--exaple-5s7b.com)
* examƿle.com (xn--examle-62b.com)
* examᴘle.com (xn--examle-e35b.com)

## Dry-run mode


## TLD support

| TLD   | Support      |
|-------|--------------|
| **gTLDs** |
| .com  | :warning: partial - only latin and lisu script |
| .org  | :warning: partial - Korean and Chinese missing |
| .net  | :warning: partial - only latin and lisu script |
| **ccTLDs** |
| .ag | :x: no |
| .ar | :x: no |
| .at  | :white_check_mark: complete |
| .au | :large_blue_circle: IDN not supported |
| .be| :x: no |
| .br | :x: no |
| .ca | :large_blue_circle: [not applicable](https://cira.ca/assets/Documents/Legal/IDN/faq.pdf) |
| .ch | :white_check_mark: complete |
| .cn | :x: no |
| .co | :x: no |
| .cz | :x: no |
| .de | :white_check_mark: complete |
| .dk | :white_check_mark: complete |
| .es | :x: no |
| .eu | :x: no |
| .fi | :x: no |
| .fm | :x: no |
| .fr | :white_check_mark: complete |
| .gr | :x: no |
| .hu | :x: no |
| .hr | :x: no |
| .ie | :x: no |
| .in | :x: no |
| .io | :x: no |
| .ir | :large_blue_circle: IDN not supported |
| .is | :x: no |
| .it | :x: no |
| .jp | :x: no |
| .me | :x: no |
| .nl | :large_blue_circle: IDN not supported |
| .no | :white_check_mark: complete |
| .pl | :x: no |
| .pm | :white_check_mark: complete |
| .рф (rf) | :x: no |
| .rs | :x: no |
| .ru | :large_blue_circle: IDN not supported |
| .tf | :white_check_mark: complete |
| .tr | :x: no |
| .tv | :x: no |
| .tw | :x: no |
| .uk | :large_blue_circle: IDN not supported |
| .us | :large_blue_circle: IDN not supported |
| .wf | :white_check_mark: complete |
| .yt | :white_check_mark: complete |
| **sTLDs** |
| .biz | :x: no |
| .info | :x: no |
| .name | :x: no |

# Limitations

## Lack of support for all TLDs

## Big data

Not the buzzword - this tools creates a large amount of permutations. 
If your domain name is long enough, there are millions of possible doppelganger domains. Atm, this tool works in RAM only. 
So if you try to check a large number of domains and your system is ~straight outta memory~ running out of memory, this tool will fall back to check only domains where exactly one character has been replaced.
This is not a big limitation though, as most mailicious actors will try to change as little characters as possible when creating phishing domans. 

If I have time I'll add support for big data sets in the future.

## DNS-Queries



# TODOs

* Add support to perform round-robin queries to a set of user selectable dns servers
* 

