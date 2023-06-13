const { NessusParser } = require('../src/nessus-js')
const fs = require('fs')
const path = require('path')

const file = fs.readFileSync(path.join(__dirname, '__testdata__', 'scan.nessus'))
const file2 = fs.readFileSync(path.join(__dirname, '__testdata__', 'scan2.nessus'))
const file3 = fs.readFileSync(path.join(__dirname, '__testdata__', 'scan3.nessus'))

test('Should parse nessus compliance file', () => {
  const output = NessusParser(file)

  expect(output.policy.policyName).toBe('Audit Cloud Infrastructure')
  expect(output.policy.preferences.serverPreferences.preferences.length).toBe(52)
  expect(output.policy.preferences.pluginPreferences.items.length).toBe(742)
  expect(output.policy.familySelection.familyItems.length).toBe(54)
  expect(output.policy.individualPluginSelection.pluginItems.length).toBe(3)
  expect(output.report.reportItems.length).toBe(86)
  expect(output.report.reportItems[0]).toStrictEqual({
    cm: {
      auditFile: 'CIS_Microsoft_Azure_Foundations_L1_v1.1.0.audit',
      checkId: 'af5bd955a4843a16157b895f6d1270861c0c61fed7eb6c3cd13c8a41aab8221a',
      checkName: "9.10 Ensure that 'HTTP Version' is the latest, if used to run the web app",
      functionalId: '374edc0aee',
      info: `Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version.
Rationale:
Newer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.
HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.`,
      informationalId: '6536ae291b8d46099b05074c7929e6f26f8fb5b996999e9969243e8dfac0a48e',
      policyValue: 'PASSED',
      reference:
        '800-171|3.14.1,800-53|SI-2,CSCv7|2.2,CSF|ID.RA-1,CSF|PR.IP-12,ITSG-33|SI-2,LEVEL|1NS,NESA|T7.6.2,NESA|T7.7.1,NIAv2|AM38,NIAv2|AM39,NIAv2|PR9,NIAv2|SS14b,SWIFT-CSCv1|2.2',
      result: 'PASSED',
      solution: `Using Console:
1. Login to Azure Portal using https://portal.azure.com
2. Go to App Services
3. Click on each App
4. Under Setting section, Click on Application settings
5. Set HTTP version to 2.0 under General settings
NOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third party certificate.
Using Command Line:
To set HTTP 2.0 version for an existing app, run the following command:
az webapp config set --resource-group &lt;RESOURCE_GROUP_NAME&gt; --name &lt;APP_NAME&gt; --http20-enabled true`,
      source: 'custom',
    },
    compliance: 'true',
    description: `\"9.10 Ensure that 'HTTP Version' is the latest, if used to run the web app\" : [PASSED]

Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version.
Rationale:
Newer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements and also verify the compatibility and support provided for any additional software against the update revision that is selected.
HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.

Solution:
Using Console:
1. Login to Azure Portal using https://portal.azure.com 2. Go to App Services 3. Click on each App 4. Under Setting section, Click on Application settings 5. Set HTTP version to 2.0 under General settings NOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-encrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to your app with HTTP/2, either buy an App Service Certificate for your app's custom domain or bind a third party certificate.
Using Command Line:
To set HTTP 2.0 version for an existing app, run the following command:
az webapp config set --resource-group &lt;RESOURCE_GROUP_NAME&gt; --name &lt;APP_NAME&gt; --http20-enabled true

See Also: https://workbench.cisecurity.org/files/2269

Reference: 800-171|3.14.1,800-53|SI-2,CSCv7|2.2,CSF|ID.RA-1,CSF|PR.IP-12,ITSG-33|SI-2,LEVEL|1NS,NESA|T7.6.2,NESA|T7.7.1,NIAv2|AM38,NIAv2|AM39,NIAv2|PR9,NIAv2|SS14b,SWIFT-CSCv1|2.2

Policy Value:
PASSED`,
    fname: 'azure_compliance_check.nbin',
    plugin: {
      family: 'Policy Compliance',
      id: '79357',
      modificationDate: '2020/08/17',
      name: 'Microsoft Azure Compliance Checks',
      publicationDate: '2015/08/14',
      type: 'local',
    },
    port: '0',
    protocol: 'tcp',
    riskFactor: 'None',
    scriptVersion: '$Revision: 1.153 $',
    severity: '0',
    solution: null,
    svcName: 'general',
  })
})

test('Should parse nessus vulnerability file', () => {
  const output = NessusParser(file2)

  expect(output.policy.policyName).toBe('Advanced Scan')
  expect(output.policy.preferences.serverPreferences.preferences.length).toBe(60)
  expect(output.policy.preferences.pluginPreferences.items.length).toBe(742)
  expect(output.policy.familySelection.familyItems.length).toBe(54)
  expect(output.policy.individualPluginSelection.pluginItems.length).toBe(5)
  expect(output.report.reportItems.length).toBe(20)
  expect(output.report.reportItems[0]).toStrictEqual({
    cpe: undefined,
    cve: undefined,
    cvss3BaseScore: undefined,
    cvss3Vector: undefined,
    cvssBaseScore: undefined,
    cvssScoreSource: undefined,
    cvssVector: undefined,
    cwe: undefined,
    description: `Nessus did not enable local checks on the remote host. This does not necessarily indicate a problem with the scan. Credentials may not have been provided, local checks may not be available for the target, the target may not have been identified, or another issue may have occurred that prevented local checks from being enabled. See plugin output for details.

This plugin reports informational findings related to local checks not being enabled. For failure information, see plugin 21745 :
'Authentication Failure - Local Checks Not Run'.`,
    fname: 'hostlevel_checks_skipped.nasl',
    iavt: undefined,
    plugin: {
      family: 'Settings',
      id: '117886',
      modificationDate: '2020/08/25',
      name: 'Local Checks Not Enabled (info)',
      output: `
The following issues were reported :

  - Plugin      : no_local_checks_credentials.nasl
    Plugin ID   : 110723
    Plugin Name : No Credentials Provided
    Message     : 
Credentials were not provided for detected SSH service.
`,
      publicationDate: '2018/10/02',
      type: 'summary',
    },
    port: '0',
    protocol: 'tcp',
    riskFactor: 'None',
    scriptVersion: '1.6',
    seeAlso: undefined,
    severity: '0',
    solution: 'n/a',
    svcName: 'general',
    synopsis: 'Local checks were not enabled.',
    vulnPublicationDate: undefined,
    xref: 'IAVB:0001-B-515',
  })
})

test('Should parse empty nessus report file', () => {
  const output = NessusParser(file3)

  expect(output.policy.policyName).toBe('Basic Scan')
  expect(output.policy.preferences.serverPreferences.preferences.length).toBe(87)
  expect(output.policy.preferences.pluginPreferences.items.length).toBe(933)
  expect(output.policy.familySelection.familyItems.length).toBe(59)
  expect(output.policy.individualPluginSelection.pluginItems.length).toBe(5)
  expect(output.report.reportItems.length).toBe(0)
})
