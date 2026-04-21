import xml.etree.ElementTree as ET


def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []

    for port in root.findall(".//port"):
        state = port.find("state").get("state")

        if state == "open":
            port_id = port.get("portid")
            service = port.find("service").get("name")

            results.append((port_id, service))

    return results