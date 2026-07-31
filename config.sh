cloudflare_settings() {
    cat <<'JSON'
{
    "0rtt": "on",
    "advanced_ddos": "off",
    "always_online": "off",
    "always_use_https": "off",
    "automatic_https_rewrites": "off",
    "brotli": "on",
    "browser_cache_ttl": 0,
    "browser_check": "off",
    "cache_level": "aggressive",
    "challenge_ttl": 604800,
    "ciphers": [],
    "cname_flattening": "flatten_at_root",
    "development_mode": "off",
    "early_hints": "off",
    "ech": "off",
    "edge_cache_ttl": 7200,
    "email_obfuscation": "off",
    "filter_logs_to_cloudflare": "off",
    "hotlink_protection": "off",
    "http2": "on",
    "http3": "on",
    "ip_geolocation": "on",
    "ipv6": "on",
    "log_to_cloudflare": "on",
    "long_lived_grpc": "off",
    "max_upload": 100,
    "min_tls_version": "1.0",
    "minify": { "css": "off", "html": "off", "js": "off" },
    "mirage": "off",
    "mobile_redirect": { "status": "off", "mobile_subdomain": null, "strip_uri": false },
    "opportunistic_encryption": "off",
    "opportunistic_onion": "off",
    "orange_to_orange": "off",
    "origin_error_page_pass_thru": "off",
    "origin_max_http_version": "1",
    "polish": "off",
    "pq_keyex": "off",
    "prefetch_preload": "off",
    "privacy_pass": "off",
    "proxy_read_timeout": 100,
    "pseudo_ipv4": "off",
    "replace_insecure_js": "off",
    "response_buffering": "off",
    "rocket_loader": "off",
    "security_header": {
        "strict_transport_security": {
            "enabled": false,
            "max_age": 0,
            "include_subdomains": false,
            "preload": false,
            "nosniff": false
        }
    },
    "security_level": "essentially_off",
    "server_side_exclude": "off",
    "sort_query_string_for_cache": "off",
    "ssl": "flexible",
    "tls_1_2_only": "off",
    "tls_1_3": "zrt",
    "tls_client_auth": "off",
    "true_client_ip_header": "off",
    "visitor_ip": "on",
    "waf": "off",
    "webp": "off",
    "websockets": "on"
}
JSON
}

cloudflare_configuration() {
    cat <<'JSON'
{
    "workers": {
        "scripts": { "clarkn-meet": { "script-settings": {} } },
        "domains": [
            { "hostname": "meet.clarkn.co.jp",     "service": "clarkn-meet" },
            { "hostname": "meet.forbestrates.com", "service": "clarkn-meet" },
            { "hostname": "meet.rankbestrate.com", "service": "clarkn-meet" }
        ]
    },

    "zones": {
        "hiroshimajobnavi.com": {
            "settings": { "ssl": "full" },
            "dns_records": [
                { "type": "A", "name": "hiroshimajobnavi.com",     "content": "34.111.141.225", "proxied": true, "ttl": 1 },
                { "type": "A", "name": "www.hiroshimajobnavi.com", "content": "34.111.141.225", "proxied": true, "ttl": 1 }
            ],
            "email_routing": {
                "rules": {
                    "catch_all": {
                        "enabled":  true,
                        "actions":  [{ "type": "forward", "value": ["info@clarkn.co.jp"] }],
                        "matchers": [{ "type": "all" }]
                    }
                }
            }
        },

        "notatel.com": {
            "dns_records": [
                { "type": "CNAME", "name": "sip.notatel.com",       "content": "sip.telnyx.com", "proxied": false, "ttl": 1 },
                { "type": "SRV",   "name": "_sip._udp.notatel.com", "data": { "service": "_sip", "proto": "_udp", "name": "notatel.com", "priority": 10, "weight": 10, "port": 5060, "target": "sip.notatel.com" }, "ttl": 1 }
            ]
        },

        "bestratereview.com": {
            "dns_records": [
                { "type": "A",   "name": "bestratereview.com",     "content": "35.192.114.80", "proxied": true,  "ttl": 1 },
                { "type": "A",   "name": "www.bestratereview.com", "content": "35.192.114.80", "proxied": true,  "ttl": 1 },
                { "type": "MX",  "name": "bestratereview.com",     "content": "smtp.google.com", "proxied": false, "ttl": 1, "priority": 1 },
                { "type": "TXT", "name": "bestratereview.com",     "content": "v=spf1 include:_spf.google.com ~all", "proxied": false, "ttl": 1 },
                { "type": "TXT", "name": "bestratereview.com",     "content": "google-site-verification=1O4KHQCY_QaBmRlMHA_WUU3LGeqjmKr_4JN25L5_ybQ", "proxied": false, "ttl": 1 }
            ]
        },

        "clarkn.co.jp": {
            "dns_records": [
                { "type": "MX",  "name": "clarkn.co.jp",     "content": "smtp.google.com", "proxied": false, "ttl": 1, "priority": 1 },
                { "type": "TXT", "name": "clarkn.co.jp",     "content": "v=spf1 include:_spf.google.com ~all", "proxied": false, "ttl": 1 },
                { "type": "TXT", "name": "clarkn.co.jp",     "content": "google-site-verification=ZsBDgLNcr70Rc7e6dF47J7pbLp435l1CF-hHyf6EaQM", "proxied": false, "ttl": 1 },
                { "type": "TXT", "name": "clarkn.co.jp",     "content": "google-site-verification=ZH2D3QODde7h7X2yI299oREgSXmMcPbtKjtl122vmqg", "proxied": false, "ttl": 1 },
                { "type": "A",   "name": "uni.clarkn.co.jp", "content": "219.211.176.140", "proxied": false, "ttl": 1 }
            ]
        },

        "forbestrates.com": {
            "dns_records": [
                { "type": "A", "name": "forbestrates.com",     "content": "35.192.114.80", "proxied": true, "ttl": 1 },
                { "type": "A", "name": "www.forbestrates.com", "content": "35.192.114.80", "proxied": true, "ttl": 1 }
            ]
        },

        "rankbestrate.com": {
            "dns_records": [
                { "type": "A", "name": "rankbestrate.com",     "content": "35.192.114.80", "proxied": true, "ttl": 1 },
                { "type": "A", "name": "www.rankbestrate.com", "content": "35.192.114.80", "proxied": true, "ttl": 1 }
            ]
        },

        "southtowntattoocollective.com": {
            "rulesets": {
                "phases": {
                    "http_request_dynamic_redirect": {
                        "name":  "Redirect Rules",
                        "kind":  "zone",
                        "phase": "http_request_dynamic_redirect",
                        "rules": [
                            {
                                "expression":        "(http.host eq \"southtowntattoocollective.com\")",
                                "action":            "redirect",
                                "action_parameters": { "from_value": { "target_url": { "expression": "concat(\"https://tattoocollectivereno.com\", http.request.uri.path)" }, "status_code": 301, "preserve_query_string": true } },
                                "enabled":           true
                            },
                            {
                                "expression":        "(http.host eq \"www.southtowntattoocollective.com\")",
                                "action":            "redirect",
                                "action_parameters": { "from_value": { "target_url": { "expression": "concat(\"https://www.tattoocollectivereno.com\", http.request.uri.path)" }, "status_code": 301, "preserve_query_string": true } },
                                "enabled":           true
                            }
                        ]
                    }
                }
            },
            "email_routing": {
                "rules": {
                    "catch_all": {
                        "enabled":  true,
                        "actions":  [{ "type": "forward", "value": ["tattoocollectivereno@gmail.com"] }],
                        "matchers": [{ "type": "all" }]
                    }
                }
            }
        },

        "tattoocollectivereno.com": {
            "email_routing": {
                "rules": {
                    "catch_all": {
                        "enabled":  true,
                        "actions":  [{ "type": "forward", "value": ["tattoocollectivereno@gmail.com"] }],
                        "matchers": [{ "type": "all" }]
                    }
                }
            }
        },

        "vec4me.com": {
            "rulesets": {
                "phases": {
                    "http_request_dynamic_redirect": {
                        "name":  "Redirect Rules",
                        "kind":  "zone",
                        "phase": "http_request_dynamic_redirect",
                        "rules": [
                            {
                                "expression":        "(http.host eq \"www.vec4me.com\" and http.request.uri.path eq \"/\")",
                                "action":            "redirect",
                                "action_parameters": { "from_value": { "target_url": { "expression": "concat(\"https://www.vec4me.com/index.htm\", \"\")" }, "status_code": 301, "preserve_query_string": true } },
                                "enabled":           true
                            }
                        ]
                    }
                }
            }
        },

        "je.gy": {
            "dns_records": [
                { "type": "TXT",   "name": "je.gy",                 "content": "v=spf1 include:_spf.mx.cloudflare.net include:icloud.com ~all", "proxied": false, "ttl": 1 },
                { "type": "CNAME", "name": "sig1._domainkey.je.gy", "content": "sig1.dkim.je.gy.at.icloudmailadmin.com", "proxied": false, "ttl": 1 }
            ],
            "email_routing": {
                "rules": {
                    "catch_all": {
                        "enabled":  true,
                        "actions":  [{ "type": "forward", "value": ["minersneedcoolshoes@gmail.com"] }],
                        "matchers": [{ "type": "all" }]
                    }
                }
            }
        },

        "valgrid.co": {
            "email_routing": {
                "rules": {
                    "catch_all": {
                        "enabled":  true,
                        "actions":  [{ "type": "forward", "value": ["valgrid0011@gmail.com"] }],
                        "matchers": [{ "type": "all" }]
                    }
                }
            }
        }
    }
}
JSON
}

telnyx_configuration() {
    cat <<'JSON'
{
    "messaging_profiles": {
        "main": {
            "name":                     "msg-+17752000767",
            "webhook_url":              "https://sms-cloudflare-central.vec4me.workers.dev/",
            "webhook_api_version":      "2",
            "whitelisted_destinations": ["*"]
        }
    },

    "outbound_voice_profiles": {
        "main": {
            "name":                     "voice-+17752000767",
            "traffic_type":             "conversational",
            "service_plan":             "global",
            "whitelisted_destinations": ["US", "CA", "MX", "JP"]
        }
    },

    "credential_connections": {
        "main": {
            "connection_name":            "sip-+17752000767",
            "user_name":                  "user0767",
            "password":                   "${env.SIP_PASSWORD}",
            "sip_uri_calling_preference": "unrestricted",
            "inbound":                    { "generate_ringback_tone": false },
            "outbound": {
                "ani_override":                       "+17752000767",
                "ani_override_type":                  "always",
                "outbound_voice_profile_id":          "${telnyx.outbound_voice_profiles.main.id}",
                "generate_ringback_tone":             false,
                "instant_ringback_enabled":           false
            }
        }
    },

    "phone_numbers": [
        {
            "phone_number":         "+17752000767",
            "voice": {
                "connection_id":   "${telnyx.credential_connections.main.id}",
                "media_features":  { "t38_fax_gateway_enabled": true, "rtp_auto_adjust_enabled": false },
                "call_forwarding": { "call_forwarding_enabled": true, "forwards_to": "+819094141337", "forwarding_type": "always" }
            },
            "number_level_routing": "disabled",
            "external_pin":         "5669",
            "hd_voice_enabled":     false
        }
    ],

    "messaging_phone_numbers": [
        { "phone_number": "+17752000767", "messaging_profile_id": "${telnyx.messaging_profiles.main.id}" }
    ]
}
JSON
}

render_cloudflare() {
    perl -MJSON::PP -e '
        my $defaults = decode_json($ARGV[0]);
        my $configuration = decode_json($ARGV[1]);

        for my $zone (values %{$configuration->{zones}}) {
            my %settings = map {
                $_ => {value => $defaults->{$_}}
            } keys %{$defaults};

            for my $name (keys %{$zone->{settings} // {}}) {
                $settings{$name} = {value => $zone->{settings}{$name}};
            }
            $zone->{settings} = \%settings;
        }

        print JSON::PP->new->canonical->encode($configuration);
    ' "$(cloudflare_settings)" "$(cloudflare_configuration)"
}

render_telnyx() {
    perl -MJSON::PP -e '
        sub expand {
            my ($value) = @_;

            if (ref($value) eq "HASH") {
                expand($_) for values %{$value};
            } elsif (ref($value) eq "ARRAY") {
                expand($_) for @{$value};
            } elsif (defined($value) && $value =~ /^\$\{env\.([^}]+)\}$/) {
                die "config.sh: $1 is required\n"
                    unless defined($ENV{$1}) && length($ENV{$1});
                $_[0] = $ENV{$1};
            }
        }

        my $configuration = decode_json($ARGV[0]);
        expand($configuration);
        print JSON::PP->new->canonical->encode($configuration);
    ' "$(telnyx_configuration)"
}

apply_configuration() {
    provider=$1
    configuration=$2
    shift 2
    printf '%s' "$configuration" | ./build/fconf "$provider" - "$@"
}

cloudflare_json=$(render_cloudflare) || exit 1
telnyx_json=$(render_telnyx) || exit 1

apply_configuration cloudflare "$cloudflare_json" "$@" || exit 1
apply_configuration telnyx "$telnyx_json" "$@" || exit 1
