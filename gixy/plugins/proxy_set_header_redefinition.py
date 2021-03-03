import gixy
from gixy.plugins.plugin import Plugin


class proxy_set_header_redefinition(Plugin):
    """
    Incorrect example:
        server {
            proxy_set_header X-Request-Id $request_id;
            location / {
                proxy_set_header Host www.example.org;
            }
        }
    """
    summary = 'Nested "proxy_set_header" drops parent headers.'
    severity = gixy.severity.UNSPECIFIED
    description = ('"proxy_set_header" replaces ALL parent headers. '
                   'See documentation: http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header')
    help_url = 'https://github.com/yandex/gixy/blob/master/docs/en/plugins/proxysetheaderredefinition.md'
    directives = ['server', 'location', 'if']
    options = {'headers': set(['*'])}

    def __init__(self, config):
        super(proxy_set_header_redefinition, self).__init__(config)
        self.interesting_headers = self.config.get('headers')

    def audit(self, directive):
        if not directive.is_block:
            # Skip all not block directives
            return

        actual_headers = get_headers(directive)
        if not actual_headers:
            return

        for parent in directive.parents:
            parent_headers = get_headers(parent)
            if not parent_headers:
                continue

            diff = parent_headers - actual_headers
            if '*' in self.interesting_headers:
                pass
            else:
                diff &= self.interesting_headers

            if len(diff):
                self._report_issue(directive, parent, diff)

            break

    def _report_issue(self, current, parent, diff):
        directives = []
        # Add headers from parent level
        directives.extend(parent.find('proxy_set_header'))
        # Add headers from current level
        directives.extend(current.find('proxy_set_header'))
        reason = 'Parent headers "{headers}" was dropped in current level'.format(headers='", "'.join(diff))
        self.add_issue(directive=directives, reason=reason)


def get_headers(directive):
    headers = directive.find('proxy_set_header')
    if not headers:
        return set()

    return set(map(lambda d: d.header, headers))
