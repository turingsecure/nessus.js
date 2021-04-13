type Scan = {
  policy: Policy
  report?: Report
}

type Report = {
  reportItems: ReportItem[]
  reportHost: string
  name: string
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
  port: string
  svcName: string
  protocol: string
  severity: string
  plugin: Plugin
  description: string
  fname: string
  riskFactor: string
  scriptVersion: string
  solution: string
  compliance: string
  cm: CM
}

type Plugin = {
  id: string
  name: string
  family: string
  modificationDate: string
  publicationDate: string
  type: string
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

function parseXml(xml: string) {
  if (typeof (window as any) !== 'undefined') {
    const parser: DOMParser = new DOMParser()

    return parser.parseFromString(xml, 'application/xml')
  }

  const jsdom = require('jsdom')

  return new jsdom.JSDOM(xml).window.document
}

/**
 *  Parses nessus xml output to a javascript object
 *
 * @param {string} xml
 *
 * @returns {Scan} The parsed output
 */
export function NessusParser(xml: string): Scan {
  const parsed = parseXml(xml)

  const policy: Policy = {
    policyName: parsed.getElementsByTagName('policyName')[0].innerHTML,
    preferences: {
      serverPreferences: {
        preferences: []
      },
      pluginPreferences: {
        items: []
      }
    },
    familySelection: {
      familyItems: []
    },
    individualPluginSelection: {
      pluginItems: []
    }
  }

  for (const serverPreference of parsed.getElementsByTagName('preference')) {
    policy.preferences.serverPreferences.preferences.push({
      name: serverPreference.getElementsByTagName('name')[0].innerHTML,
      value: serverPreference.getElementsByTagName('value')[0].innerHTML
    })
  }

  for (const pluginPreference of parsed.getElementsByTagName('item')) {
    policy.preferences.pluginPreferences.items.push({
      name: pluginPreference.getElementsByTagName('pluginName')[0].innerHTML,
      pluginId: pluginPreference.getElementsByTagName('pluginId')[0].innerHTML,
      fullName: pluginPreference.getElementsByTagName('fullName')[0].innerHTML,
      preferenceName: pluginPreference.getElementsByTagName('preferenceName')[0].innerHTML,
      preferenceType: pluginPreference.getElementsByTagName('preferenceType')[0].innerHTML,
      preferenceValues: pluginPreference.getElementsByTagName('preferenceValues')[0].innerHTML,
      selectedValues: pluginPreference.getElementsByTagName('selectedValue')[0].innerHTML
    })
  }

  for (const familyItem of parsed.getElementsByTagName('FamilyItem')) {
    policy.familySelection.familyItems.push({
      familyName: familyItem.getElementsByTagName('FamilyName')[0].innterHTML,
      status: familyItem.getElementsByTagName('Status')[0].innterHTML
    })
  }

  for (const pluginSelection of parsed.getElementsByTagName('PluginItem')) {
    policy.individualPluginSelection.pluginItems.push({
      pluginId: pluginSelection.getElementsByTagName('PluginId')[0].innerHTML,
      pluginName: pluginSelection.getElementsByTagName('PluginName')[0].innerHTML,
      family: pluginSelection.getElementsByTagName('Family')[0].innerHTML,
      status: pluginSelection.getElementsByTagName('Status')[0].innerHTML
    })
  }

  const report: Report = {
    name: parsed.getElementsByTagName('Report')[0].getAttribute('name'),
    reportHost: parsed.getElementsByTagName('ReportHost')[0].getAttribute('name'),
    reportItems: []
  }

  for (const reportItem of parsed.getElementsByTagName('ReportItem')) {
    report.reportItems.push({
      port: reportItem.getAttribute('port'),
      svcName: reportItem.getAttribute('svc-name'),
      protocol: reportItem.getAttribute('protocol'),
      severity: reportItem.getAttribute('severity'),
      plugin: {
        id: reportItem.getAttribute('pluginID'),
        name: reportItem.getAttribute('pluginName'),
        family: reportItem.getAttribute('pluginFamily'),
        modificationDate: reportItem.getElementsByTagName('plugin_modification_date')[0].innerHTML,
        publicationDate: reportItem.getElementsByTagName('plugin_publication_date')[0].innerHTML,
        type: reportItem.getElementsByTagName('plugin_type')[0].innerHTML
      },
      description: reportItem.getElementsByTagName('description')[0].innerHTML,
      fname: reportItem.getElementsByTagName('fname')[0].innerHTML,
      compliance: reportItem.getElementsByTagName('compliance')[0].innerHTML,
      riskFactor: reportItem.getElementsByTagName('risk_factor')[0].innerHTML,
      scriptVersion: reportItem.getElementsByTagName('script_version')[0].innerHTML,
      solution: reportItem.getElementsByTagName('solution')[0]
        ? reportItem.getElementsByTagName('solution')[0].innerHTML
        : undefined,
      cm: {
        checkName: reportItem.getElementsByTagName('cm:compliance-check-name')[0].innerHTML,
        source: reportItem.getElementsByTagName('cm:compliance-source')[0].innerHTML,
        auditFile: reportItem.getElementsByTagName('cm:compliance-audit-file')[0].innerHTML,
        checkId: reportItem.getElementsByTagName('cm:compliance-check-id')[0].innerHTML,
        policyValue: reportItem.getElementsByTagName('cm:compliance-policy-value')[0].innerHTML,
        functionalId: reportItem.getElementsByTagName('cm:compliance-functional-id')[0].innerHTML,
        info: reportItem.getElementsByTagName('cm:compliance-info')[0].innerHTML,
        result: reportItem.getElementsByTagName('cm:compliance-result')[0].innerHTML,
        informationalId: reportItem.getElementsByTagName('cm:compliance-informational-id')[0]
          .innerHTML,
        reference: reportItem.getElementsByTagName('cm:compliance-reference')[0].innerHTML,
        solution: reportItem.getElementsByTagName('cm:compliance-solution')[0].innerHTML
      }
    })
  }

  const scan: Scan = {
    policy,
    report
  }

  return scan
}
