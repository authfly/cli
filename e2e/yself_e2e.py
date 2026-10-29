# YSELF e2e for yself.link (public pages + editor). Prints no secrets; leaves the wmaster page as it was.
import re, sys, struct, zlib, requests
from urllib.parse import urljoin
pw = open('/root/secrets/stalwart-wmaster-password').read().strip()
Y, A = 'https://yself.link', 'https://accounts.yself.link'
ok = True
def check(n, c, m):
    global ok; ok &= bool(c); print('PASS' if c else 'FAIL', n, m)
csrf = lambda t: re.search(r'name="csrf" value="([^"]+)"', t).group(1)
r = requests.get(Y + '/')
check(1, r.status_code == 200 and 'data-testid="hero"' in r.text and 'cta-signin' in r.text, 'landing: hero + sign-in CTA')
r = requests.get(Y + '/wmaster')
check(2, r.status_code == 200 and 'og:title' in r.text and 'rel="noopener nofollow ugc"' in r.text and 'data-testid="profile-link"' in r.text
      and 'script-src' not in r.headers.get('Content-Security-Policy', 'script-src'), 'public page: OG, rel ugc, links, CSP without scripts')
check(3, requests.get(Y + '/nobody-zz-404').status_code == 404 and requests.get(Y + '/WMaster', allow_redirects=False).status_code == 301, '404 unknown handle, 301 uppercase')
check(4, requests.get(Y + '/avatars/..%2f..%2fetc%2fpasswd').status_code == 404, 'avatar path traversal 404')
s = requests.Session()
r = s.get(Y + '/me')
act = re.search(r'<form[^>]*action="([^"]+)"', r.text).group(1)
r = s.post(urljoin(r.url, act), data={'csrf': csrf(r.text), 'identifier': 'wmaster@yself.link', 'password': pw})
check(5, r.url.startswith(Y + '/me') and 'data-testid="profile-form"' in r.text and 'data-testid="preview-frame"' in r.text, 'sign in -> editor with preview')
c = csrf(r.text)
check(6, s.post(Y + '/me/links', data={'csrf': 'bad', 'title': 't', 'url': 'https://x.y'}, allow_redirects=False).status_code == 403, 'bad CSRF 403')
check(7, s.post(Y + '/me/links', data={'csrf': c, 'title': 't', 'url': 'javascript:alert(1)'}, allow_redirects=False).status_code == 422, 'javascript: URL refused')
check(8, s.post(Y + '/me/profile', data={'csrf': c, 'handle': 'admin'}, allow_redirects=False).status_code == 422, 'reserved handle refused')
x = s.post(Y + '/me/links', data={'csrf': c, 'title': 'e2e-tmp', 'url': 'https://example.com/e2e', 'enabled': '1'}, allow_redirects=False)
p1, p2 = s.get(Y + '/me'), s.get(Y + '/me')
check(9, x.status_code == 303 and 'authfly-info' in p1.text and 'authfly-info' not in p2.text and 'e2e-tmp' in requests.get(Y + '/wmaster').text, 'add link: PRG, one-time flash, visible publicly')
lid = re.search(r'id="link-(\d+)"(?:(?!id="link-).)*?e2e-tmp', p1.text, re.S).group(1)
check(10, s.post(Y + '/me/links/%s/move' % lid, data={'csrf': c, 'dir': 'up'}, allow_redirects=False).status_code == 303, 'move link up')
check(11, s.post(Y + '/me/links/%s/delete' % lid, data={'csrf': c}, allow_redirects=False).status_code == 303 and 'e2e-tmp' not in requests.get(Y + '/wmaster').text, 'delete link')
def png(w, h):
    raw = b''.join(b'\x00' + b'\x20\x80\xe0' * w for _ in range(h))
    ch = lambda t, d: struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + ch(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)) + ch(b'IDAT', zlib.compress(raw)) + ch(b'IEND', b'')
check(12, s.post(Y + '/me/avatar', data={'csrf': c}, files={'avatar': ('a.svg', b'<svg onload=alert(1)>', 'image/svg+xml')}, allow_redirects=False).status_code == 422, 'SVG avatar refused')
had = re.search(r'src="/avatars/([a-f0-9]{32}\.jpg)"', s.get(Y + '/me').text)
if not had:
    x = s.post(Y + '/me/avatar', data={'csrf': c}, files={'avatar': ('a.png', png(300, 200), 'image/png')}, allow_redirects=False)
    m = re.search(r'src="/avatars/([a-f0-9]{32}\.jpg)"', requests.get(Y + '/wmaster').text)
    img = requests.get(Y + '/avatars/' + m.group(1)) if m else None
    check(13, x.status_code == 303 and img is not None and img.headers.get('Content-Type') == 'image/jpeg' and img.content[:2] == b'\xff\xd8', 'avatar upload -> JPEG served')
    check(14, s.post(Y + '/me/avatar/delete', data={'csrf': c}, allow_redirects=False).status_code == 303 and 'data-testid="initials"' in requests.get(Y + '/wmaster').text, 'remove avatar -> initials')
else:
    check(13, True, 'avatar upload skipped (profile has a photo)')
x = s.post(Y + '/auth/logout', headers={'Origin': Y}, allow_redirects=True)
check(15, s.get(Y + '/me?format=json', allow_redirects=False).status_code == 302, 'logout ends the yself session')
p = s.get(A + '/account/apps')
if 'name="csrf"' in p.text:
    s.post(A + '/auth/sign-out', data={'csrf': csrf(s.get(A + '/auth/sign-out').text)})
print('RESULT', 'ALL PASS' if ok else 'FAILURES'); sys.exit(0 if ok else 1)
