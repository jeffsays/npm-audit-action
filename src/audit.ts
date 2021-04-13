/* eslint-disable @typescript-eslint/naming-convention */
import {spawnSync, SpawnSyncReturns} from 'child_process'
import stripAnsi from 'strip-ansi'

const SPAWN_PROCESS_BUFFER_SIZE = 10485760 // 10MiB
export enum VULNERABILITIY_TYPE {
  INFO = 'Contains info severity vulnerabilities',
  LOW = 'Contains low severity vulnerabilities',
  MODERATE = 'Contains moderate severity vulnerabilities',
  HIGH = 'Contains high severity vulnerabilities',
  CRITICAL = 'Contains critical severity vulnerabilities'
}
export class Audit {
  stdout = '{}'
  private status: number | null = null

  public run(
    auditLevel: string,
    productionFlag: string,
    jsonFlag: string
  ): void {
    try {
      const auditOptions: Array<string> = ['audit', '--audit-level', auditLevel]

      if (productionFlag === 'true') {
        auditOptions.push('--production')
      }

      if (jsonFlag === 'true') {
        auditOptions.push('--json')
      }

      const result: SpawnSyncReturns<string> = spawnSync('npm', auditOptions, {
        encoding: 'utf-8',
        maxBuffer: SPAWN_PROCESS_BUFFER_SIZE
      })

      if (result.error) {
        throw result.error
      }
      if (result.status === null) {
        throw new Error('the subprocess terminated due to a signal.')
      }
      if (result.stderr && result.stderr.length > 0) {
        throw new Error(result.stderr)
      }

      this.status = result.status
      this.stdout = result.stdout
    } catch (error) {
      throw error
    }
  }

  public foundVulnerability(): boolean {
    // `npm audit` return 1 when it found vulnerabilities
    return this.status === 1
  }

  public strippedStdout(): string {
    return `# Warning: This PR contains vulnerabilites\n### Please check the output of \`npm audit\` and try to update the dependencies if possible\n<details><summary>Audit JSON output</summary>\`\`\`\n${stripAnsi(
      this.stdout
    )}\n\`\`\`</details>`
  }

  public getHighestVulnerabilityLevel(): string {
    const {
      metadata: {vulnerabilities}
    } = JSON.parse(this.stdout)
    let highestVulnerabilitlevel = ''

    if (vulnerabilities != null && typeof vulnerabilities === 'object') {
      Object.entries<number>(vulnerabilities).forEach(([severity, amount]) => {
        if (severity === 'critical' && amount > 0) {
          return (highestVulnerabilitlevel = VULNERABILITIY_TYPE.CRITICAL)
        }
        if (severity === 'high' && amount > 0) {
          return (highestVulnerabilitlevel = VULNERABILITIY_TYPE.HIGH)
        }
        if (severity === 'moderate' && amount > 0) {
          return (highestVulnerabilitlevel = VULNERABILITIY_TYPE.MODERATE)
        }
        if (severity === 'low' && amount > 0) {
          return (highestVulnerabilitlevel = VULNERABILITIY_TYPE.LOW)
        }
        if (severity === 'info' && amount > 0) {
          return (highestVulnerabilitlevel = VULNERABILITIY_TYPE.INFO)
        }
      })
    }
    return highestVulnerabilitlevel
  }
}
