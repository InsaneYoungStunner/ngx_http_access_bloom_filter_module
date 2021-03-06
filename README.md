# Description
**ngx_access_bloom_filter_module** - a access monitor that uses an internal bitmap to judge the access permission via bloom filter.It is designed to solve the problem with massively arbitrary forbidden IP addresses.This means NGINX can agilely estimate the access permission of IP address.Meanwhile,inevitably,NGINX can generate some false positive results also,so I make a white list.You can use it to protect the rightful IP from false positive results.

# Important to know
* **ngx_http_access_bloom_filter_module** is currently not supported for ~~Unix domain protocol~~ and ~~IPV6~~.
* keyword ~~all~~ is currently not supported,but I will offer this ability ,soon.

# Directives

## deny_numbers_bf
#### Syntax: &ensp; &ensp; &ensp; &ensp; deny_numbers_bf &ensp;&ensp; deny-ip-numbers
#### Default: &ensp; &ensp; &ensp; &ensp; none
#### Context: &ensp; &ensp; &ensp; &ensp; http , server , local
* Defines the number of IP address which can be forbidden in a bloom filter context.We will calculate the number of hash buckets by it.

## allow_bf
#### Syntax: &ensp; &ensp; &ensp; &ensp; allow_bf &ensp;&ensp; IP-address
#### Default: &ensp; &ensp; &ensp; &ensp; none
#### Context: &ensp; &ensp; &ensp; &ensp; http , server , local
* This parameter defines the IP address which has to be pushed to reserve the rightful IP on the allow list.

## deny_bf
#### Syntax: &ensp; &ensp; &ensp; &ensp; deny_bf &ensp;&ensp; IP-address

#### Default: &ensp; &ensp; &ensp; &ensp; none
#### Context: &ensp; &ensp; &ensp; &ensp; http , server , local
* This parameter defines the IP address which has to be hashed to reserve the forbidden IP on the bitmap.

# Example
#### As an example,you can use this module like this:

```
 location / {
deny_numbers_bf 2;
deny_bf  192.168.1.1;
allow_bf 192.168.1.0/24;
deny_bf  10.1.1.0/16;
}

```
# Feedback
If you find any bugs or have any good ideas, please email me and I will try to help.I would appreciate every kind of feedback or problem reports.  
* *Mail: lxw865116882@gmail.com*

# License
MIT


