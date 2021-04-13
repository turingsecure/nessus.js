const { NessusParser } = require('../src/nessus-js')
const fs = require('fs')
const path = require('path')

const file = fs.readFileSync(path.join(__dirname, '__testdata__', 'scan.nessus'))

test('Should parse nessus file', () => {
  const output = NessusParser(file)

  expect(output.policy.policyName).toBe('Audit Cloud Infrastructure')
  expect(output.policy.preferences.serverPreferences.preferences.length).toBe(52)
  expect(output.policy.preferences.pluginPreferences.items.length).toBe(742)
  expect(output.policy.familySelection.familyItems.length).toBe(54)
  expect(output.policy.individualPluginSelection.pluginItems.length).toBe(3)
  expect(output.report.reportItems.length).toBe(86)
})
