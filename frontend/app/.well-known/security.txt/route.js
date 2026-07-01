import { NextResponse } from 'next/server';

const SECURITY_TXT = `# VibeSafe security policy
#
# We take security reports seriously. If you find a vulnerability in
# vibesafe.dev or in the VibeSafe product itself, please report it here.
# Reports about issues in your own repositories should go through the normal
# scan flow at https://vibesafe.dev/scan instead.

Contact: mailto:security@vibesafe.dev
Contact: https://vibesafe.dev/security
Expires: 2027-05-01T00:00:00.000Z
Encryption: https://vibesafe.dev/pgp-key.txt
Preferred-Languages: en
Canonical: https://vibesafe.dev/.well-known/security.txt
Policy: https://vibesafe.dev/security
Acknowledgments: https://vibesafe.dev/security#hall-of-fame
Hiring: https://vibesafe.dev/careers
`;

export async function GET() {
  return new NextResponse(SECURITY_TXT, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
}
