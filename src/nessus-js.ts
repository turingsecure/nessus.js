type Scan = {
  policy: Policy
  reports: Report[]
}

type Report = {
  reportItems: ReportItem[]
  reportHost: string
  name: string
  hostProperties: HostProperties
}

type Policy = {
  policyName: string
  preferences: Preferences
  familySelection: FamilySelection
  individualPluginSelection: IndividualPluginSelection
}

type IndividualPluginSelection = {
  pluginItems: PluginItem[]
}

type PluginItem = {
  pluginId: string
  pluginName: string
  family: string
  status: string
}

type FamilySelection = {
  familyItems: FamilyItem[]
}

type FamilyItem = {
  familyName: string
  status: string
}
type Preferences = {
  serverPreferences: ServerPreferences
  pluginPreferences: PluginPreferences
}

type ServerPreferences = {
  preferences: Preference[]
}

type Preference = {
  name: string
  value: string
}

type PluginPreferences = {
  items: PluginPreferencesItem[]
}

type PluginPreferencesItem = {
  name: string
  pluginId: string
  fullName: string
  preferenceName: string
  preferenceType: string
  preferenceValues: string
  selectedValues: string
}

type ReportItem = {
  port: string | null
  svcName: string | null
  protocol: string | null
  severity: string | null
  plugin: Plugin
  description: string
  fname: string
  riskFactor: string
  scriptVersion: string
  solution: string | null
  synopsis?: string
  seeAlso?: string
  cpe?: string
  xref?: string
  vulnPublicationDate?: string
  cwe?: string
  cve?: string
  cvss3BaseScore?: string
  cvss3Vector?: string
  cvssBaseScore?: string
  cvssScoreSource?: string
  cvssVector?: string
  iavt?: string
  compliance?: string
  cm?: CM
}

type Plugin = {
  id: string | null
  name: string | null
  family: string | null
  modificationDate: string
  publicationDate: string
  type: string
  output?: string
}

type CM = {
  checkName: string
  source: string
  auditFile: string
  checkId: string
  policyValue: string
  functionalId: string
  info: string
  result: string
  informationalId: string
  reference: string
  solution: string
}

type HostProperties = {
  hostEndTimestamp: string
  hostEnd: string
  cpe4: string
  cpe3: string
  cpe2: string
  cpe1: string
  cpe0: string
  patchSummaryTotalCves: string
  cpe: string
  os: string
  operatingSystemConf: string
  operatingSystemMethod: string
  sshFingerprint: string
  systemType: string
  operatingSystem: string
  sapNetweaverAsBanner: string
  tracerouteHop1: string
  tracerouteHop0: string
  sinfpMlPrediction: string
  sinfpSignature: string
  hostFqdn: string
  hostRdns: string
  hostIp: string
  hostStartTimestamp: string
  hostStart: string
}

function parseXml(xml: string) {
  if (typeof (window as any) !== 'undefined') {
    const parser: DOMParser = new DOMParser()

    return parser.parseFromString(xml, 'application/xml')
  }

  const jsdom = require('jsdom')

  return new jsdom.JSDOM(xml).window.document
}

function camelize(str: string) {
  return str
    .slice(1, str.length - 1)
    .toLowerCase()
    .replace(/[^a-zA-Z0-9]+(.)/g, (m, chr) => chr.toUpperCase())
}

function createComplianceItem(reportItem: HTMLElement): ReportItem | null {
  return {
    port: reportItem.getAttribute('port'),
    svcName: reportItem.getAttribute('svc_name'),
    protocol: reportItem.getAttribute('protocol'),
    severity: reportItem.getAttribute('severity'),
    plugin: {
      id: reportItem.getAttribute('pluginID'),
      name: reportItem.getAttribute('pluginName'),
      family: reportItem.getAttribute('pluginFamily'),
      modificationDate: reportItem.getElementsByTagName('plugin_modification_date')?.[0]?.innerHTML,
      publicationDate: reportItem.getElementsByTagName('plugin_publication_date')?.[0]?.innerHTML,
      type: reportItem.getElementsByTagName('plugin_type')?.[0]?.innerHTML,
    },
    description: reportItem.getElementsByTagName('description')?.[0]?.innerHTML,
    fname: reportItem.getElementsByTagName('fname')?.[0]?.innerHTML,
    riskFactor: reportItem.getElementsByTagName('risk_factor')?.[0]?.innerHTML,
    scriptVersion: reportItem.getElementsByTagName('script_version')?.[0]?.innerHTML,
    solution: reportItem.getElementsByTagName('solution')?.[0]
      ? reportItem.getElementsByTagName('solution')?.[0]?.innerHTML
      : null,
    compliance: reportItem.getElementsByTagName('compliance')?.[0]?.innerHTML,
    cm: {
      checkName: reportItem.getElementsByTagName('cm:compliance-check-name')?.[0]?.innerHTML,
      source: reportItem.getElementsByTagName('cm:compliance-source')?.[0]?.innerHTML,
      auditFile: reportItem.getElementsByTagName('cm:compliance-audit-file')?.[0]?.innerHTML,
      checkId: reportItem.getElementsByTagName('cm:compliance-check-id')?.[0]?.innerHTML,
      policyValue: reportItem.getElementsByTagName('cm:compliance-policy-value')?.[0]?.innerHTML,
      functionalId: reportItem.getElementsByTagName('cm:compliance-functional-id')?.[0]?.innerHTML,
      info: reportItem.getElementsByTagName('cm:compliance-info')?.[0]?.innerHTML,
      result: reportItem.getElementsByTagName('cm:compliance-result')?.[0]?.innerHTML,
      informationalId: reportItem.getElementsByTagName('cm:compliance-informational-id')?.[0]
        ?.innerHTML,
      reference: reportItem.getElementsByTagName('cm:compliance-reference')?.[0]?.innerHTML,
      solution: reportItem.getElementsByTagName('cm:compliance-solution')?.[0]?.innerHTML,
    },
  }
}

function createVulnerabilityItem(reportItem: HTMLElement): ReportItem | null {
  return {
    port: reportItem.getAttribute('port'),
    svcName: reportItem.getAttribute('svc_name'),
    protocol: reportItem.getAttribute('protocol'),
    severity: reportItem.getAttribute('severity'),
    plugin: {
      id: reportItem.getAttribute('pluginID'),
      name: reportItem.getAttribute('pluginName'),
      family: reportItem.getAttribute('pluginFamily'),
      modificationDate: reportItem.getElementsByTagName('plugin_modification_date')?.[0]?.innerHTML,
      publicationDate: reportItem.getElementsByTagName('plugin_publication_date')?.[0]?.innerHTML,
      type: reportItem.getElementsByTagName('plugin_type')?.[0]?.innerHTML,
      output: reportItem.getElementsByTagName('plugin_output')[0]?.innerHTML,
    },
    description: reportItem.getElementsByTagName('description')?.[0]?.innerHTML,
    fname: reportItem.getElementsByTagName('fname')?.[0]?.innerHTML,
    riskFactor: reportItem.getElementsByTagName('risk_factor')?.[0]?.innerHTML,
    scriptVersion: reportItem.getElementsByTagName('script_version')?.[0]?.innerHTML,
    solution: reportItem.getElementsByTagName('solution')?.[0]
      ? reportItem.getElementsByTagName('solution')?.[0]?.innerHTML
      : null,
    synopsis: reportItem.getElementsByTagName('synopsis')?.[0]?.innerHTML,
    seeAlso: reportItem.getElementsByTagName('see_also')?.[0]?.innerHTML,
    cpe: reportItem.getElementsByTagName('cpe')?.[0]?.innerHTML,
    xref: reportItem.getElementsByTagName('xref')?.[0]?.innerHTML,
    vulnPublicationDate: reportItem.getElementsByTagName('vuln_publication_date')?.[0]?.innerHTML,
    cwe: reportItem.getElementsByTagName('cwe')?.[0]?.innerHTML,
    cve: reportItem.getElementsByTagName('cve')?.[0]?.innerHTML,
    iavt: reportItem.getElementsByTagName('iavt')?.[0]?.innerHTML,
    cvss3BaseScore: reportItem.getElementsByTagName('cvss3_base_score')?.[0]?.innerHTML,
    cvss3Vector: reportItem.getElementsByTagName('cvss3_vector')?.[0]?.innerHTML,
    cvssBaseScore: reportItem.getElementsByTagName('cvss_base_score')?.[0]?.innerHTML,
    cvssScoreSource: reportItem.getElementsByTagName('cvss_score_source')?.[0]?.innerHTML,
    cvssVector: reportItem.getElementsByTagName('cvss_vector')?.[0]?.innerHTML,
  }
}

/**
 *  Parses nessus xml output to a javascript object
 *
 * @param {string} xml
 *
 * @returns {Scan} The parsed output
 */
export function NessusParser(xml: string): Scan | null {
  const parsed = parseXml(xml)
  if (!parsed) {
    return null
  }

  const policy: Policy = {
    policyName: parsed.getElementsByTagName('policyName')?.[0]?.innerHTML,
    preferences: {
      serverPreferences: {
        preferences: [],
      },
      pluginPreferences: {
        items: [],
      },
    },
    familySelection: {
      familyItems: [],
    },
    individualPluginSelection: {
      pluginItems: [],
    },
  }

  for (const serverPreference of parsed.getElementsByTagName('preference') || []) {
    policy.preferences.serverPreferences.preferences.push({
      name: serverPreference.getElementsByTagName('name')?.[0]?.innerHTML,
      value: serverPreference.getElementsByTagName('value')?.[0]?.innerHTML,
    })
  }

  for (const pluginPreference of parsed.getElementsByTagName('item') || []) {
    policy.preferences.pluginPreferences.items.push({
      name: pluginPreference.getElementsByTagName('pluginName')?.[0]?.innerHTML,
      pluginId: pluginPreference.getElementsByTagName('pluginId')?.[0]?.innerHTML,
      fullName: pluginPreference.getElementsByTagName('fullName')?.[0]?.innerHTML,
      preferenceName: pluginPreference.getElementsByTagName('preferenceName')?.[0]?.innerHTML,
      preferenceType: pluginPreference.getElementsByTagName('preferenceType')?.[0]?.innerHTML,
      preferenceValues: pluginPreference.getElementsByTagName('preferenceValues')?.[0]?.innerHTML,
      selectedValues: pluginPreference.getElementsByTagName('selectedValue')?.[0]?.innerHTML,
    })
  }

  for (const familyItem of parsed.getElementsByTagName('FamilyItem') || []) {
    policy.familySelection.familyItems.push({
      familyName: familyItem.getElementsByTagName('FamilyName')?.[0]?.innterHTML,
      status: familyItem.getElementsByTagName('Status')?.[0]?.innterHTML,
    })
  }

  for (const pluginSelection of parsed.getElementsByTagName('PluginItem') || []) {
    policy.individualPluginSelection.pluginItems.push({
      pluginId: pluginSelection.getElementsByTagName('PluginId')?.[0]?.innerHTML,
      pluginName: pluginSelection.getElementsByTagName('PluginName')?.[0]?.innerHTML,
      family: pluginSelection.getElementsByTagName('Family')?.[0]?.innerHTML,
      status: pluginSelection.getElementsByTagName('Status')?.[0]?.innerHTML,
    })
  }

  const reportName: string = parsed.getElementsByTagName('Report')?.[0]?.getAttribute('name')
  const reportHosts: Array<HTMLElement> = [...parsed.getElementsByTagName('ReportHost')]
  const reports: Array<Report> = []

  reportHosts.forEach((reportHost) => {
    const report: Report = {
      name: reportName,
      reportHost: JSON.stringify(reportHost.getAttribute('name')),
      reportItems: [],
      hostProperties: {
        hostEndTimestamp: '',
        hostEnd: '',
        cpe4: '',
        cpe3: '',
        cpe2: '',
        cpe1: '',
        cpe0: '',
        patchSummaryTotalCves: '',
        cpe: '',
        os: '',
        operatingSystemConf: '',
        operatingSystemMethod: '',
        sshFingerprint: '',
        systemType: '',
        operatingSystem: '',
        sapNetweaverAsBanner: '',
        tracerouteHop1: '',
        tracerouteHop0: '',
        sinfpMlPrediction: '',
        sinfpSignature: '',
        hostFqdn: '',
        hostRdns: '',
        hostIp: '',
        hostStartTimestamp: '',
        hostStart: '',
      },
    }

    for (const reportItem of <any>reportHost.getElementsByTagName('ReportItem') || []) {
      if (reportItem.getElementsByTagName('compliance')?.[0]?.innerHTML === 'true') {
        const complianceItem: ReportItem | null = createComplianceItem(reportItem)
        if (complianceItem) {
          report.reportItems.push(complianceItem)
        }
      } else {
        const vulnerabilityItem: ReportItem | null = createVulnerabilityItem(reportItem)
        if (vulnerabilityItem) {
          report.reportItems.push(vulnerabilityItem)
        }
      }
    }

    const childArray = [
      ...(<any>reportHost.getElementsByTagName('HostProperties')?.[0]?.children || []),
    ]
    if (childArray?.length) {
      const hostProperties: HostProperties = childArray.reduce(
        (accumulated: Object, child: Element) => ({
          ...accumulated,
          [camelize(JSON.stringify(child.getAttribute('name')))]: child.innerHTML,
        }),
        {}
      )
      report.hostProperties = hostProperties
    }
    reports.push(report)
  })

  const scan: Scan = {
    policy,
    reports,
  }

  return scan
}
