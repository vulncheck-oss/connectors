# from vclib.connector import ConnectorVulnCheck


def collect_epss(conn, config_state: dict) -> list:
    """Collect all data for epss

    Args:
        conn (ConnectorVulnCheck): The VulnCheck connector

    Returns:
        list: A list of STIX objects
    """
    conn.helper.connector_logger.info("[EPSS] Starting collection")
    entities = conn.client.get_epss()
    stix_objects = []

    conn.helper.connector_logger.info("[EPSS] Parsing data into STIX objects")
    for entity in entities:
        conn.helper.connector_logger.debug(
            "[EPSS] Creating vulnerability",
            {"cve": entity.cve},
        )
        vuln = conn.converter_to_stix.create_vulnerability(
            cve=entity.cve,
            epss_score=entity.epss_score,
            epss_percentile=entity.epss_percentile,
        )
        stix_objects.append(vuln)

    conn.helper.connector_logger.info("[EPSS] Data Source Completed!")
    return stix_objects
