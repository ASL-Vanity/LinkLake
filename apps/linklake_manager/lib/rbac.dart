enum ManagementRole {
  administrator,
  operator,
  auditor;

  static ManagementRole parse(Object? value) => switch (value?.toString()) {
    'administrator' => ManagementRole.administrator,
    'operator' => ManagementRole.operator,
    _ => ManagementRole.auditor,
  };
}

class RoleCapabilities {
  const RoleCapabilities(this.role);

  final ManagementRole role;

  bool get isAdministrator => role == ManagementRole.administrator;
  bool get canWritePolicies => role != ManagementRole.auditor;
  bool get canManageAlerts => role != ManagementRole.auditor;
  bool get canManageUsers => isAdministrator;
  bool get canManageSessions => isAdministrator;
  bool get canManageApiTokens => isAdministrator;
  bool get canManageFleet => isAdministrator;
  bool get canViewFleet => isAdministrator;
  bool get canManageTrafficControl => isAdministrator;
  bool get canManageTotp => role != ManagementRole.auditor;
}

class DashboardRequest {
  const DashboardRequest(this.key, this.path, {this.object = false});

  final String key;
  final String path;
  final bool object;
}

List<DashboardRequest> dashboardRequestPlan(ManagementRole role) {
  final requests = <DashboardRequest>[
    const DashboardRequest('status', '/api/v1/status', object: true),
    const DashboardRequest('metrics', '/api/v1/metrics', object: true),
    const DashboardRequest('clients', '/api/v1/clients'),
    const DashboardRequest('p2p', '/api/v1/p2p/nodes'),
    const DashboardRequest('audit', '/api/v1/audit?limit=50'),
    const DashboardRequest('tcp', '/api/v1/tcp-tunnels'),
    const DashboardRequest('udp', '/api/v1/udp-tunnels'),
    const DashboardRequest('http', '/api/v1/http-routes'),
    const DashboardRequest('sni', '/api/v1/sni-routes'),
    const DashboardRequest('secret', '/api/v1/secret-tunnels'),
    const DashboardRequest('socks5', '/api/v1/socks5-proxies'),
    const DashboardRequest('proxy', '/api/v1/http-proxies'),
    const DashboardRequest('group', '/api/v1/port-groups'),
    const DashboardRequest(
      'alerts',
      '/api/v1/alerts/events?active=true&limit=100',
    ),
    const DashboardRequest('alertRules', '/api/v1/alerts/rules'),
  ];
  if (role == ManagementRole.administrator) {
    requests.addAll(const [
      DashboardRequest('users', '/api/v1/users'),
      DashboardRequest('sessions', '/api/v1/sessions'),
      DashboardRequest('apiTokens', '/api/v1/api-tokens'),
      DashboardRequest('fleet', '/api/v1/fleet/overview', object: true),
    ]);
  }
  return requests;
}

List<String> visibleDestinationIds(ManagementRole role) => [
  'overview',
  'clients',
  'tcp',
  'udp',
  'group',
  'http',
  'sni',
  'secret',
  'socks5',
  'proxy',
  'p2p',
  if (role == ManagementRole.administrator) 'fleet',
  'alerts',
  if (role == ManagementRole.administrator) 'users',
  'diagnostics',
  'audit',
];
