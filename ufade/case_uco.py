import platform
import uuid

apple_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, "Apple")
os_name = platform.system()
os_version = platform.version()
os_release = platform.release()

host_platform = (os_name, os_release, os_version)

host_os = " ".join(host_platform)

case_context = {
    "kb": "http://example.org/kb/",
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-identity": "https://ontology.unifiedcyberontology.org/uco/identity/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "xsd": "http://www.w3.org/2001/XMLSchema#"
}

os_dict = {
    "iPhone": "iOS",
    "iPod": "iOS",
    "Watch": "watchOS",
    "iPad": "iPadOS",
    "AppleTV": "tvOS",
    "AudioAccessory": "audioOS",
}

def backup_case_json(case_device, case_backup):

    case_json = {
        "@context": case_context
    }
    device_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, case_device["UDID"])
    backup_case = []
    tool = f"UFADE {case_backup['tool_version']}"
    tool_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, tool)

    acquisition = {
        "@id": "kb:investigativeaction-" + str(uuid.uuid4()),
        "@type": "case-investigation:InvestigativeAction",
        "uco-core:name": "acquired",
        "uco-core:description": case_backup["description"],
        "uco-action:startTime": {
            "@type": "xsd:dateTime",
            "@value": case_backup["startTime"]
        },
        "uco-action:endTime": {
            "@type": "xsd:dateTime",
            "@value": case_backup["endTime"]
        },
        "uco-action:instrument": {
            "@id": "kb:configuredtool-" + str(tool_uuid)
        },
        "uco-action:object": [
            {
                "@id": "kb:device-" + str(device_uuid)
            }
        ]
    }
    results = []
    file_results = []
    for fileobject in case_backup["Files"]:
        sha256 = fileobject["SHA256"]
        file_type = fileobject["Type"]
        file_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, str(sha256))
        result = {
            "@id": f"kb:{file_type}-{file_uuid}"
        }
        results.append(result)
        file_result = {
            "@id": f"kb:{file_type}-{file_uuid}",
             "@type": [
                "uco-observable:File",
            ],
             "uco-core:hasFacet": [
            {
                "@id": "kb:file-facet-" + str(uuid.uuid4()),
                "@type": "uco-observable:FileFacet",
                "uco-observable:extension": fileobject["extension"],
                "uco-observable:fileName": fileobject["FileName"],
                "uco-observable:isDirectory": fileobject["isDirectory"],
                "uco-observable:sizeInBytes": fileobject["Filesize"],
            },
            {
                "@id": "kb:content-data-facet-" + str(uuid.uuid4()),
                "@type": "uco-observable:ContentDataFacet",
                "uco-observable:hash": [
                    {
                        "@id": "kb:hash-" + str(uuid.uuid4()),
                        "@type": "uco-types:Hash",
                        "uco-types:hashMethod": "SHA256",
                        "uco-types:hashValue": {
                            "@type": "xsd:hexBinary",
                            "@value": fileobject["SHA256"]
                        }
                    }
                ]
            }
            ]
        }
        file_results.append(file_result)
    acquisition["uco-action:result"] = results
    created_by = "Christian Peter (Developer) [www.cp-df.com]"
    creator_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, created_by)
    creator = {
        "@id": "kb:person-" + str(creator_uuid),
        "@type": "uco-identity:Person",
        "uco-core:name": created_by
    }

    tool_entry = {
            "@id": "kb:configuredtool-" + str(tool_uuid),
            "@type": "uco-tool:ConfiguredTool",
            "uco-core:name": "Universal Forensic Apple Device Extractor (UFADE)",
            "uco-tool:toolType": "Extraction",
            "uco-tool:creator": {
                "@id": creator["@id"]
            },
            "uco-tool:version": case_backup["tool_version"],
            "uco-configuration:usesConfiguration": {
                "@id": "kb:configuration-" + str(uuid.uuid4()),
                "@type": "uco-configuration:Configuration",
                "uco-configuration:configurationEntry": [
                    {
                        "@id": "kb:configuration-entry-" + str(uuid.uuid4()),
                        "@type": "uco-configuration:ConfigurationEntry",
                        "uco-configuration:itemName": "ExtractionMethod",
                        "uco-configuration:itemValue": case_backup["ExtractionMethod"]
                    },
                    {
                        "@id": "kb:configuration-entry-" + str(uuid.uuid4()),
                        "@type": "uco-configuration:ConfigurationEntry",
                        "uco-configuration:itemName": "ExtractionType",
                        "uco-configuration:itemValue": case_backup["ExtractionType"]
                    },
                    {
                        "@id": "kb:configuration-entry-" + str(uuid.uuid4()),
                        "@type": "uco-configuration:ConfigurationEntry",
                        "uco-configuration:itemName": "HostOS",
                        "uco-configuration:itemValue": host_os
                    }
                ]
            }
        }

    backup_case.append(acquisition)
    backup_case.append(creator)
    backup_case.append(tool_entry)
    for file in file_results:
        backup_case.append(file)

    #organization is always Apple for UFADE 
    organization = {
        "@id": "kb:organization-" + str(apple_uuid),
        "@type": "uco-identity:Organization",
        "uco-core:name": "Apple"
    }
    backup_case.append(organization)
    #The DeviceID is calculated from the UDID
    device = {
        "@id": "kb:device-" + str(device_uuid),
        "@type": "uco-observable:Device",
    }
    facets = []
    #The DeviceFacetID is calculated from the SerialNumber
    snr = case_device["serialNumber"]
    d_type = case_device["deviceType"]
    device_facet_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, snr)
    dev_facet = {
        "@id": "kb:device-facet-" + str(device_facet_uuid),
        "@type": "uco-observable:DeviceFacet",
        "uco-observable:manufacturer": {
            "@id": organization["@id"]
        },
        "uco-observable:deviceType": d_type,
        "uco-observable:model": case_device["model"],
        "uco-observable:serialNumber": snr,
    }
    facets.append(dev_facet)
    if case_device.get("IMEI") is not None:
        imei = case_device["IMEI"]
        mobile_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, imei)
        has_imei = True
    else:
        mobile_uuid = uuid.uuid4()
        has_imei = False
   
    md_facet = {
        "@id": "kb:mobile-device-facet-" + str(mobile_uuid),
        "@type": "uco-observable:MobileDeviceFacet",
    }
    if has_imei:
        md_facet["uco-observable:IMEI"] = imei
    md_facet["drafting:localeLanguage"] = case_device["localeLanguage"]
    md_facet["uco-observable:storageCapacityInBytes"] = case_device["storageCapacityInBytes"]

    wifi_mac_facet = None
    if case_device.get("WifiAddress") not in [None, " ", ""]:
        has_wmac = True
        w_mac = case_device["WifiAddress"]
        wifi_adress_facet_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, w_mac)
        wifi_mac_facet = {
            "@id": "kb:wifi-address-facet-" + str(wifi_adress_facet_uuid),
            "@type": "uco-observable:WifiAddressFacet",
            "uco-observable:addressValue": w_mac,
        }
    else:
        has_wmac = False

    bt_mac_facet = None
    if case_device.get("BluetoothAddress") not in [None, " ", ""]:
        has_bmac = True
        b_mac = case_device["BluetoothAddress"]
        bt_adress_facet_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, b_mac)
        bt_mac_facet = {
            "@id": "kb:wifi-address-facet-" + str(bt_adress_facet_uuid),
            "@type": "uco-observable:BluetoothAddressFacet",
            "uco-observable:addressValue": b_mac,
        }
    else:
        has_bmac = False

    device["uco-core:hasFacet"] = facets

    facets.append(md_facet)

    if has_wmac:
        facets.append(wifi_mac_facet)
    if has_bmac:
        facets.append(bt_mac_facet)

    backup_case.append(device)
    #Operating System Info
    software_type = os_dict.get(d_type, "iOS")
    software_version = case_device.get("Software")
    software_full = f"{software_type} {software_version}"
    software_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, software_full)
    operating_system = {
        "@id": "kb:operating-system-" + str(software_uuid),
        "@type": [
            "uco-observable:OperatingSystem",
            "uco-observable:Software"
        ],
        "uco-core:name": software_type,
        "uco-core:hasFacet": {
            "@id": "kb:software-facet-" + str(uuid.uuid4()),
            "@type": "uco-observable:SoftwareFacet",
            "uco-observable:manufacturer": {
                "@id": organization["@id"]
            },
            "uco-observable:version": software_version
        }
    }
    backup_case.append(operating_system)

    relation_os_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, str(device_uuid) + str(software_uuid))
    relation_os = {
        "@id": "kb:relationship-" + str(relation_os_uuid),
        "@type": "uco-observable:ObservableRelationship",
        "uco-core:kindOfRelationship": "Has_Operating_System",
        "uco-core:isDirectional": True,
        "uco-core:source": {
            "@id": device["@id"]
        },
        "uco-core:target": {
            "@id": operating_system["@id"]
        }
    }
    backup_case.append(relation_os)
    case_json["@graph"] = backup_case

    return case_json

   