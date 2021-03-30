interface Scan {
  reportItems?: ReportItem[]
}

interface ReportItem {
  port: number
  svc_name: string
  protocol: string
  severity: string
  plugin: Plugin
  description: string
  fname: string
  riskFactor: string
  scriptVersion: string
  solution: string
  synopsis: string
  output: string
}

interface Plugin {
  id: string
  name: string
  family: string
  modificationDate: string
  publicationDate: string
  type: string
}

/**
 *  Parses nessus xml output to a javascript object
 *
 * @param {string} xml
 *
 * @returns {Scan} The parsed output
 */
export function BurpParser(xml: string): Scan {
  // eslint-disable-next-line no-undef
  const parser: DOMParser = new DOMParser()
  const parsed: Document = parser.parseFromString(xml, 'application/xml')

  const scan: Scan = {}

  return scan
}
