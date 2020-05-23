
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = '-----BEGIN CERTIFICATE-----\n' +
    'MIIDBzCCAe+gAwIBAgIJQP4ngmEWaAlAMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV\n' +
    'BAMTFmRldi15enk2aXduOS5hdXRoMC5jb20wHhcNMjAwNTE5MTUwNDAzWhcNMzQw\n' +
    'MTI2MTUwNDAzWjAhMR8wHQYDVQQDExZkZXYteXp5Nml3bjkuYXV0aDAuY29tMIIB\n' +
    'IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzzuxJni7eX6XiRJlNcQIuB0V\n' +
    '948xia0rPcaLYhQPO5m3c0AXcWPa/FuoLkwI6iO2LkwCohnPr1ch5+FZTUZ5jEX0\n' +
    '4NInS5vGAjABLgiXn+nyKhlVgEEmsQhhqBe95Tbz7bVxkp72FVjCHhTXAW9YCi3Z\n' +
    '0tlEL4k/QCZXuc739GLWdM9SogXwO829ZSOmh6kEJffZYG2+b75LGWJi4+ns2c2+\n' +
    'tNz1hYh1uq23OZF7Is0Wn7E0LM53AJ8CE1+hrGnSsf1cyMyfVMYu3Zdcz+N0G3Dc\n' +
    'Dbw6OvjJc7o0WSId7sBamunFh98sev//xgLRnflNeaNu+Zd+NGuHy3bvpleLXQID\n' +
    'AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSUSTT+c+RiSGMq/kS/\n' +
    'NsKNkciVhzAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAAirekOP\n' +
    'eUweOioqXLMeEOvK83BiNWtpJdSHaTUoPHHPDp/aZPMieNKHfq04+iaIEW+LFu7G\n' +
    '9CWJhH+Fi6KoXUCRciiLQwvg2Mhe/1j36yZU37Ppk8VtICQoo3k3e9nd7hWeuafM\n' +
    'L+JJ0M21m2tSyxodPnKGwIu+VYlrjmGV+uxP/SsDaxiA3MLvXNhcCaJl2YPz5hDg\n' +
    '/i9r4k6LCZjzHP12uLxYIkTZ0G575+4TdJv6+28imXx8rSfuv1YNvW3eoXuK1Gd2\n' +
    'aY8U8+R4anewmYjhIxDS+29QDLqzdGWNRagrOKn6jKsCC3+8a7fQjxdGiikYkEaE\n' +
    'YAU/IPXTcGO8FwY=\n' +
    '-----END CERTIFICATE-----';

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
