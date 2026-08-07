'use strict';

      const WORDS = {
        en: {
          previewFleetSync: 'Preview sync', applyFleetSync: 'Apply sync', fleetSyncPreviewed: 'Sync preview completed.', fleetSyncApplied: 'TCP/UDP policies synchronized.',
          title: 'LinkLake Management Console', console: 'Management Console', appearance: 'Appearance', themeSystem: 'System', themeLight: 'Light', themeDark: 'Dark', palette: 'Palette', paletteLake: 'Lake', paletteOcean: 'Ocean', paletteJade: 'Jade', paletteViolet: 'Violet', globalSearch: 'Global search', globalSearchPlaceholder: 'Search clients, policies, ports, domains or IDs', noSearchResults: 'No matching clients or policies.',
          loginTitle: 'Sign in to LinkLake', loginIntro: 'Use an administrator account to manage clients, forwarding services and runtime health.', username: 'Username', password: 'Password', usernamePlaceholder: 'Administrator username', passwordPlaceholder: 'Password', signIn: 'Sign in', newPassword: 'New password', confirmPassword: 'Confirm password', changePassword: 'Change password', passwordRequirement: 'Use at least 12 characters.', passwordsMismatch: 'The passwords do not match.', totpCode: 'Verification code', totpPlaceholder: '6-digit code', totpRequired: 'Enter the 6-digit code from your authenticator app.',
          overview: 'Overview', overviewSubtitle: 'Service health, live traffic and active alerts at a glance.', metrics: 'Runtime metrics', metricsSubtitle: 'Protocol activity, failure composition and infrastructure health.', services: 'Services', p2p: 'P2P network', p2pSubtitle: 'Inspect direct candidates, NAT mappings and relay fallback.', fleet: 'Multi-cloud', fleetHelp: 'Monitor LinkLake servers and define preferred and failover entry points.', newFleetPeer: 'Add server', editFleetPeer: 'Edit server', fleetTokenHelp: 'The management token is read from an environment variable on this server.', region: 'Region', priority: 'Priority', weight: 'Weight', latency: 'Latency', device: 'Device', tokenEnvironment: 'Token environment', preferredEntry: 'Preferred entry', onlineServers: 'Online servers', failoverEntries: 'Failover entries', noFleetPeers: 'No multi-cloud servers configured.', fleetSaved: 'Server entry saved.', fleetDeleted: 'Server entry deleted.', confirmFleetDelete: 'Delete server {name}?', fleetConflict: 'Placement conflict', activity: 'Activity', activitySubtitle: 'Filter and inspect administrator, policy and tunnel events.', portGroupsShort: 'Ports', secretShort: 'Secret', httpProxyShort: 'Proxy',
          alertManagement: 'Alert management', alertManagementHelp: 'Configure persistent rules and inspect firing or resolved events.', newAlertRule: 'New rule', editAlertRule: 'Edit rule', alertRuleHelp: 'Choose a metric, threshold, evaluation window and notification channels.', notificationChannels: 'Notification channels', channelsConfigured: 'Webhook: {webhook} · SMTP: {smtp}', configured: 'configured', notConfigured: 'not configured', alertMetric: 'Metric', threshold: 'Threshold', alertTarget: 'Target', severity: 'Severity', comparator: 'Comparator', evaluationWindow: 'Evaluation window (seconds)', cooldown: 'Cooldown (seconds)', alertTargetPlaceholder: 'Optional client ID or policy kind:ID', metricClientOffline: 'Client offline', metricPolicyUnavailable: 'Policy unavailable', metricAuthenticationFailures: 'Authentication failures', metricTrafficRate: 'Traffic rate', metricActiveConnections: 'Active connections', metricCertificateDays: 'Certificate days remaining', severityInfo: 'Info', severityWarning: 'Warning', severityCritical: 'Critical', noAlertEvents: 'No active alerts.', noAlertRules: 'No alert rules.', alertRuleSaved: 'Alert rule saved.', alertRuleDeleted: 'Alert rule deleted.', confirmDeleteAlertRule: 'Delete this alert rule?', firing: 'Firing', resolved: 'Resolved',
          serverOnline: 'Server online', refresh: 'Refresh', refreshed: 'Updated', language: 'Language', signOut: 'Sign out', roleAdministrator: 'Administrator', roleOperator: 'Operator', roleAuditor: 'Auditor', role: 'Role', sessionExpires: 'Session expires {time}', authenticationSession: 'Cookie session',
          trafficTrend: 'Traffic trend', trafficTrendHelp: 'Server-side traffic history is persisted for up to 30 days.', inbound: 'Inbound', outbound: 'Outbound', activeSessions: 'Active sessions', noTrendData: 'Waiting for enough samples to calculate throughput.', noTrafficRange: 'No traffic in the selected range.',
          serviceHealth: 'Service health', serviceHealthHelp: 'Online policies by protocol.', certificateSummary: 'Certificates', alerts: 'Alerts', noAlerts: 'No active alerts.', clients: 'Clients', forwardingServices: 'Forwarding services', p2pNodes: 'Fresh / total P2P nodes', totalTraffic: 'Total traffic', configIssues: 'Configuration issues',
          protocolActivity: 'Protocol activity', protocolActivityHelp: 'Current active connections and sessions.', failureOverview: 'Failure overview', failureOverviewHelp: 'Cumulative failures since server startup.', serverUptime: 'Server uptime', requestsTotal: 'Requests', failuresTotal: 'Failures', reconnects: 'Reconnects', authenticationFailures: 'Authentication failures',
          tcpMetrics: 'TCP', udpMetrics: 'UDP', webMetrics: 'Web / TLS', proxyMetrics: 'Forward proxies', p2pMetrics: 'P2P', certificateMetrics: 'Certificates / ACME', systemMetrics: 'System', active: 'Active', pending: 'Pending', sessions: 'Sessions', packets: 'Packets', traffic: 'Traffic in / out', rejected: 'Rejected', failed: 'Failed', completed: 'Completed', timeouts: 'Timeouts', transportErrors: 'Transport errors', drops: 'Drops', connections: 'Connections', direct: 'Direct', relay: 'Relay', managed: 'Managed', valid: 'Valid', expiring: 'Expiring soon', expired: 'Expired', nearestExpiry: 'Nearest expiry', orders: 'Orders', renewals: 'Renewals', challenges: 'HTTP-01 challenges',
          newPolicy: 'New policy', editPolicy: 'Edit', duplicate: 'Duplicate', enable: 'Enable', disable: 'Disable', delete: 'Delete', cancel: 'Cancel', save: 'Save', create: 'Create', saving: 'Saving…', search: 'Search', searchPolicies: 'Search by name, endpoint or client', status: 'Status', allStatuses: 'All statuses', online: 'Online', offline: 'Offline', enabled: 'Enabled', disabled: 'Disabled', all: 'All', policyCount: '{visible} of {total}', noPolicies: 'No policies match the current filters.', confirmDelete: 'Delete this policy and close its active sessions?', policyCreated: 'Policy created.', policyUpdated: 'Policy updated.', policyDeleted: 'Policy deleted.', policyEnabled: 'Policy enabled.', policyDisabled: 'Policy disabled.', exportPolicies: 'Export', exportCsv: 'Export CSV', importPolicies: 'Import', selectVisible: 'Select visible', selectedPolicies: '{count} selected', migrateClient: 'Migrate client', bulkCompleted: 'Bulk operation completed.', importCompleted: '{count} policies imported.', invalidImport: 'The policy import file is invalid.', confirmBulkDelete: 'Delete {count} selected policies and close their active sessions?', trafficControl: 'Traffic control', trafficControlHelp: 'Restrict sources, new connections, daily traffic and active UTC time windows.', allowedCidrs: 'Allowed CIDRs', deniedCidrs: 'Denied CIDRs', cidrPlaceholder: 'One CIDR per line, such as 203.0.113.0/24', connectionRate: 'New connections / minute', dailyQuota: 'Daily quota (MiB)', activeWeekdays: 'Weekdays UTC (0-6)', weekdaysPlaceholder: '0,1,2,3,4 for Monday-Friday', activeWindow: 'UTC active window', usageToday: 'Used today: {value}', trafficControlSaved: 'Traffic control saved.', targetPoolHelp: 'Use commas for multiple targets and @weight for weighted routing, for example 127.0.0.1:2333@2,127.0.0.1:2444@1.',
          tcpTitle: 'TCP tunnels', tcpSubtitle: 'Expose a TCP port and forward each connection to a selected client.', udpTitle: 'UDP tunnels', udpSubtitle: 'Forward UDP datagrams with session tracking and bandwidth controls.', portsTitle: 'Port groups', portsSubtitle: 'Manage multiple TCP or UDP port mappings as one policy.', httpTitle: 'HTTP / HTTPS routes', httpSubtitle: 'Route HTTP/1.1, HTTP/2 and native gRPC by hostname with optional automatic HTTPS.', httpTransportCapabilities: 'Public HTTP/1.1 and HTTP/2 are supported. Native gRPC uses a pooled h2c backend; HTTPS negotiates h2 with ALPN.', sniTitle: 'TLS SNI pass-through', sniSubtitle: 'Forward TLS connections by SNI without terminating TLS.', secretTitle: 'Secret tunnels', secretSubtitle: 'Credential-based private access between provider and visitor clients.', socks5Title: 'SOCKS5 proxy', socks5Subtitle: 'Expose authenticated SOCKS5 TCP and UDP access.', httpProxyTitle: 'HTTP forward proxy', httpProxySubtitle: 'Expose an authenticated HTTP and CONNECT proxy.', acmeTitle: 'ACME automation', acmeSubtitle: 'Configure certificate issuance and renewal for HTTP routes.',
          socks5CapabilitiesWithUdp: 'CONNECT and UDP ASSOCIATE are available. BIND and UDP FRAG are also available.', socks5CapabilitiesTcpOnly: 'CONNECT and BIND are available. UDP ASSOCIATE and UDP FRAG are unavailable because the UDP relay is disabled.', socks5CapabilitiesPartial: 'Available: {available}. Unavailable or not reported: {unavailable}.',
          client: 'Client', name: 'Name', tunnelName: 'Tunnel name', routeName: 'Route name', proxyName: 'Proxy name', publicPort: 'Public port', targetAddress: 'Target address', maxConnections: 'Maximum connections', bandwidthLimit: 'Bandwidth limit (B/s)', maxSessions: 'Maximum sessions', idleTimeout: 'Idle timeout (seconds)', protocol: 'Protocol', publicPorts: 'Public ports', targetHost: 'Target host', targetPorts: 'Target ports', hostname: 'Hostname', tlsMode: 'TLS mode', tlsDisabled: 'Disabled', tlsAutomatic: 'Automatic ACME', redirectHttps: 'Redirect HTTP to HTTPS', providerClient: 'Provider client', allowedVisitor: 'Allowed visitor client', anyAuthenticatedClient: 'Any authenticated client', proxyUsername: 'Proxy username', optional: 'Optional', unlimited: 'Unlimited', selectClient: 'Select a client', noClients: 'No enrolled clients are available.',
          createTcp: 'Create TCP tunnel', editTcp: 'Edit TCP tunnel', createUdp: 'Create UDP tunnel', editUdp: 'Edit UDP tunnel', createPorts: 'Create port group', editPorts: 'Edit port group', createHttp: 'Create HTTP route', editHttp: 'Edit HTTP route', createSni: 'Create SNI route', editSni: 'Edit SNI route', createSecret: 'Create secret tunnel', editSecret: 'Edit secret tunnel', createSocks5: 'Create SOCKS5 proxy', editSocks5: 'Edit SOCKS5 proxy', createHttpProxy: 'Create HTTP proxy', editHttpProxy: 'Edit HTTP proxy',
          secretCreated: 'Copy this access key now. It will not be shown again: {key}', socks5Created: 'Copy these SOCKS5 credentials now. Username: {username} Password: {password}', httpProxyCreated: 'Copy these HTTP proxy credentials now. Username: {username} Password: {password}',
          certificate: 'Certificate', certificateDisabled: 'Disabled', certificatePending: 'Pending', certificateIssuing: 'Issuing', certificateActive: 'Active', certificateRenewing: 'Renewing', certificateError: 'Error', certificateExpired: 'Expired', enableAutomaticHttps: 'Enable HTTPS', disableHttps: 'Disable HTTPS', enableRedirect: 'Enable redirect', disableRedirect: 'Disable redirect', issueCertificate: 'Issue certificate', renewCertificate: 'Renew certificate', certificateQueued: 'Certificate operation queued.', tlsUpdated: 'TLS settings updated.', routeCreatedTlsFailed: 'The route was created, but its TLS settings could not be saved. The form is now in edit mode; correct the TLS settings and save again.',
          acmeEnabled: 'Enable automatic certificate management', acmeEnvironment: 'Environment', acmeStaging: "Let's Encrypt staging", acmeProduction: "Let's Encrypt production", acmeCustom: 'Custom directory', acmeDirectory: 'Directory URL', acmeEmail: 'Contact email', renewBefore: 'Renew before expiry (days)', acmeTerms: 'I accept the certificate authority terms of service', saveAcme: 'Save ACME settings', acmeSaved: 'ACME settings saved.', acmeReady: 'ACME account registered', acmePending: 'ACME account is not registered', acmeOff: 'ACME automation is disabled',
          p2pFresh: 'Fresh', p2pStale: 'Stale', candidates: 'Candidates', age: 'Last update age', noP2pNodes: 'No P2P candidates have been registered.', mapping: 'Mapping', portMapping: 'Port mapping', rendezvous: 'Rendezvous', unknown: 'Unknown',
          searchActivity: 'Search action, subject or detail', category: 'Category', allCategories: 'All categories', categoryManagement: 'Management', categoryPolicy: 'Policies', categoryClient: 'Clients', categoryP2p: 'P2P', categoryCertificate: 'Certificates', loadMore: 'Load more', noActivity: 'No events match the current filters.', action: 'Action', subject: 'Subject', detail: 'Detail', occurredAt: 'Occurred at', auditCount: '{visible} events',
          auditLogin: 'Administrator signed in', auditLoginFailed: 'Administrator sign-in failed', auditPasswordChanged: 'Administrator password changed', auditLogout: 'Administrator signed out', auditClientEnrolled: 'Client enrolled', auditPolicyCreated: 'Policy created', auditPolicyUpdated: 'Policy updated', auditPolicyDeleted: 'Policy deleted', auditRegistered: 'Service registered', auditAcmeUpdated: 'ACME settings updated', auditCertificateStarted: 'Certificate operation started', auditCertificateSucceeded: 'Certificate operation succeeded', auditCertificateFailed: 'Certificate operation failed', auditP2pUpdated: 'P2P candidates updated', auditP2pDirect: 'P2P direct connection established', auditP2pRelay: 'P2P connection fell back to relay',
          signInFailed: 'Sign-in failed. Check the username and password.', signingIn: 'Signing in…', changeRequired: 'Change the initial password before using the management console.', changingPassword: 'Changing password…', passwordChanged: 'Password changed.', passwordChangeFailed: 'Unable to change the password. Use at least 12 characters.', signedOut: 'Signed out.', sessionExpired: 'The administrator session expired. Sign in again.', requestFailed: 'The server did not respond. Check the server and network connection.', statusFailed: 'Unable to load management data.', invalidResponse: 'The server returned an invalid response.',
          configIssueAlert: '{count} client configuration issue(s)', certificateExpiredAlert: '{count} expired certificate(s)', certificateExpiringAlert: '{count} certificate(s) expire within 30 days', authenticationFailureAlert: '{count} authentication failure(s) since startup', transportErrorAlert: '{count} transport or handshake error(s) since startup',
          accessControl: 'Access control', userManagement: 'User management', userManagementHelp: 'Create accounts, assign roles and control access.', securitySessions: 'Security & sessions', securitySessionsHelp: 'Manage two-factor authentication, API credentials and active sign-ins.', newUser: 'New user', displayName: 'Display name', lastLogin: 'Last login', actions: 'Actions', sessionId: 'Session ID', createdAt: 'Created', expiresAt: 'Expires', forcePasswordChange: 'Require password change at next sign-in', resetPassword: 'Reset password', revokeSessions: 'Revoke sessions', revoke: 'Revoke', userFormHelp: 'Passwords must contain at least 12 characters.', userCreated: 'User created.', userUpdated: 'User updated.', userDeleted: 'User deleted.', passwordReset: 'Password reset.', sessionsRevoked: 'Sessions revoked.', confirmUserDelete: 'Delete user {username}?', confirmRevokeSessions: 'Revoke every session for {username}?', confirmRevokeSession: 'Revoke this session?', never: 'Never', mustChangePassword: 'Must change password', currentSession: 'Current session', total: 'Total', searchUsers: 'Search username or display name', allRoles: 'All roles', userCount: '{visible} of {total}', twoFactorAuth: 'Two-factor authentication', totpEnabled: 'Enabled. Sign-in requires an authenticator code.', totpDisabled: 'Disabled. Password-only sign-in is active.', setupTotp: 'Set up', disableTotp: 'Disable', totpSetupHelp: 'Add the setup key or URI to your authenticator, then enter the current code.', totpDisableHelp: 'Enter the current authenticator code to disable two-factor authentication.', totpSecret: 'Setup key', provisioningUri: 'Provisioning URI', totpEnabledMessage: 'Two-factor authentication enabled.', totpDisabledMessage: 'Two-factor authentication disabled.', invalidTotp: 'The verification code is invalid.', apiTokens: 'API tokens', apiTokensHelp: 'Create scoped tokens for automation and integrations.', newApiToken: 'New token', apiToken: 'API token', apiTokenShownOnce: 'This token is shown only once. Copy it before closing.', scope: 'Scope', scopeRead: 'Read only', scopeWrite: 'Read and write', scopeAdministrator: 'Administrator', expiryDays: 'Expiry (days)', lastUsed: 'Last used', activeSignIns: 'Active sign-ins', apiTokenCreated: 'API token created.', apiTokenRevoked: 'API token revoked.', confirmApiTokenRevoke: 'Revoke API token {name}?', noApiTokens: 'No API tokens.',
          clientManagement: 'Client management', clientManagementHelp: 'Organize client identities, revoke access and rotate credentials.', searchClients: 'Search name, group, tag, platform or ID', clientGroup: 'Group', tags: 'Tags', tagsPlaceholder: 'Comma-separated tags, such as game, home, asia', notes: 'Notes', platform: 'Platform', lastSeen: 'Last seen', configStatus: 'Config', editClient: 'Edit client', rotateToken: 'Rotate token', newClientToken: 'New client token', tokenShownOnce: 'This token is shown only once. Update the client configuration before closing.', clientToken: 'Client token', copy: 'Copy', done: 'Done', clientEnabledHelp: 'Allow this identity to authenticate and receive policies', clientUpdated: 'Client updated.', clientDeleted: 'Client deleted.', tokenRotated: 'Client token rotated.', tokenCopied: 'Token copied.', confirmClientDelete: 'Delete offline client {name}? Policies that reference it must be migrated first.', confirmTokenRotation: 'Rotate the token for {name}? The previous token will stop working immediately.', clientCount: '{visible} of {total}', localConfig: 'Local', reportOnlyConfig: 'Report only', managedConfig: 'Server managed', synchronized: 'Synchronized', conflict: 'Conflict', applyFailed: 'Apply failed', unknownConfig: 'Unknown',
          allowedPorts: 'Allowed: {ports}', reservedPorts: 'reserved: {ports}', errorUnknownClient: 'The selected client does not exist.', errorInvalidName: 'The name must contain 1 to 80 characters.', errorInvalidPort: 'The public port is outside the server policy. {ports}.', errorDuplicatePort: 'This public port is already assigned.', errorInvalidTarget: 'Use a valid host:port target.', errorInvalidHostname: 'The hostname is invalid.', errorDuplicateHostname: 'The hostname is already assigned.', errorInvalidLimit: 'One of the configured limits is invalid.', errorStorage: 'Policy storage is unavailable. Check the data directory and server log.', errorUnknownPolicy: 'The policy does not exist.', errorInvalidUsername: 'The proxy username is invalid.', errorInvalidPortExpression: 'Use single ports, comma-separated lists or ascending ranges.', errorPortCountMismatch: 'Public and target port counts must match.', errorDuplicatePortInGroup: 'A port appears more than once in this group.', errorTooManyMappings: 'A port group can contain at most 256 mappings.', errorAcme: 'The ACME request failed. Check the settings, DNS and server log.'
        },
        zh: {
          previewFleetSync: '预览同步', applyFleetSync: '执行同步', fleetSyncPreviewed: '同步预览已完成。', fleetSyncApplied: 'TCP/UDP 策略同步完成。',
          title: 'LinkLake 管理控制台', console: '管理控制台', appearance: '外观', themeSystem: '跟随系统', themeLight: '浅色', themeDark: '深色', palette: '配色', paletteLake: '湖蓝', paletteOcean: '海洋', paletteJade: '翡翠', paletteViolet: '紫罗兰', globalSearch: '全局搜索', globalSearchPlaceholder: '搜索客户端、策略、端口、域名或 ID', noSearchResults: '没有匹配的客户端或策略。',
          loginTitle: '登录 LinkLake', loginIntro: '使用管理员账户登录，管理客户端、转发服务与运行状态。', username: '用户名', password: '密码', usernamePlaceholder: '管理员用户名', passwordPlaceholder: '密码', signIn: '登录', newPassword: '新密码', confirmPassword: '确认密码', changePassword: '修改密码', passwordRequirement: '密码至少需要 12 位。', passwordsMismatch: '两次输入的密码不一致。', totpCode: '动态验证码', totpPlaceholder: '6 位验证码', totpRequired: '请输入身份验证器中的 6 位动态验证码。',
          overview: '总览', overviewSubtitle: '集中查看服务健康、实时流量和活动告警。', metrics: '运行指标', metricsSubtitle: '查看协议活动、故障构成和基础设施健康状态。', services: '服务与转发', p2p: 'P2P 网络', p2pSubtitle: '查看直连候选、NAT 映射和中继回退。', fleet: '多云管理', fleetHelp: '集中监控 LinkLake 服务端，并定义首选入口与故障切换顺序。', newFleetPeer: '添加服务端', editFleetPeer: '编辑服务端', fleetTokenHelp: '管理令牌由当前服务端的环境变量读取，不写入数据库。', region: '地域', priority: '优先级', weight: '权重', latency: '延迟', device: '设备', tokenEnvironment: '令牌环境变量', preferredEntry: '首选入口', onlineServers: '在线服务端', failoverEntries: '故障切换入口', noFleetPeers: '尚未配置多云服务端。', fleetSaved: '服务端条目已保存。', fleetDeleted: '服务端条目已删除。', confirmFleetDelete: '确定删除服务端 {name} 吗？', fleetConflict: '部署冲突', activity: '活动', activitySubtitle: '筛选并检查管理员、策略和隧道事件。', portGroupsShort: '端口组', secretShort: '私密', httpProxyShort: '代理',
          alertManagement: '告警管理', alertManagementHelp: '配置持久化规则并查看触发或已恢复的事件。', newAlertRule: '新建规则', editAlertRule: '编辑规则', alertRuleHelp: '选择指标、阈值、评估窗口和通知通道。', notificationChannels: '通知通道', channelsConfigured: 'Webhook：{webhook} · SMTP：{smtp}', configured: '已配置', notConfigured: '未配置', alertMetric: '指标', threshold: '阈值', alertTarget: '目标', severity: '级别', comparator: '比较方式', evaluationWindow: '评估窗口（秒）', cooldown: '通知冷却（秒）', alertTargetPlaceholder: '可选：客户端 ID 或 策略类型:ID', metricClientOffline: '客户端离线', metricPolicyUnavailable: '策略不可用', metricAuthenticationFailures: '认证失败', metricTrafficRate: '流量速率', metricActiveConnections: '活动连接', metricCertificateDays: '证书剩余天数', severityInfo: '信息', severityWarning: '警告', severityCritical: '严重', noAlertEvents: '当前没有活动告警。', noAlertRules: '暂无告警规则。', alertRuleSaved: '告警规则已保存。', alertRuleDeleted: '告警规则已删除。', confirmDeleteAlertRule: '确定删除此告警规则吗？', firing: '触发中', resolved: '已恢复',
          serverOnline: '服务在线', refresh: '刷新', refreshed: '更新时间', language: '语言', signOut: '退出登录', roleAdministrator: '管理员', roleOperator: '运维人员', roleAuditor: '审计人员', role: '用户组', sessionExpires: '会话到期时间：{time}', authenticationSession: 'Cookie 会话',
          trafficTrend: '流量趋势', trafficTrendHelp: '服务端持久化保留最多 30 天流量历史。', inbound: '入站', outbound: '出站', activeSessions: '活跃会话', noTrendData: '正在等待足够的样本以计算实时速率。', noTrafficRange: '所选时间范围内没有流量。',
          serviceHealth: '服务健康度', serviceHealthHelp: '按协议查看在线策略数量。', certificateSummary: '证书摘要', alerts: '告警', noAlerts: '当前没有活动告警。', clients: '客户端', forwardingServices: '转发服务', p2pNodes: '新鲜 / 全部 P2P 节点', totalTraffic: '累计流量', configIssues: '配置问题',
          protocolActivity: '协议活动', protocolActivityHelp: '当前活跃连接和会话。', failureOverview: '故障概览', failureOverviewHelp: '服务启动以来的累计故障。', serverUptime: '运行时间', requestsTotal: '请求数', failuresTotal: '故障数', reconnects: '重连次数', authenticationFailures: '认证失败',
          tcpMetrics: 'TCP', udpMetrics: 'UDP', webMetrics: '网站 / TLS', proxyMetrics: '正向代理', p2pMetrics: 'P2P', certificateMetrics: '证书 / ACME', systemMetrics: '系统', active: '活跃', pending: '待配对', sessions: '会话', packets: '数据包', traffic: '入站 / 出站流量', rejected: '拒绝', failed: '失败', completed: '完成', timeouts: '超时', transportErrors: '传输错误', drops: '丢弃', connections: '连接', direct: '直连', relay: '中继', managed: '托管', valid: '有效', expiring: '即将到期', expired: '已过期', nearestExpiry: '最近到期', orders: '订单', renewals: '续期', challenges: 'HTTP-01 挑战',
          newPolicy: '新建策略', editPolicy: '编辑', duplicate: '复制', enable: '启用', disable: '停用', delete: '删除', cancel: '取消', save: '保存', create: '创建', saving: '正在保存…', search: '搜索', searchPolicies: '按名称、端点或客户端搜索', status: '状态', allStatuses: '全部状态', online: '在线', offline: '离线', enabled: '已启用', disabled: '已停用', all: '全部', policyCount: '显示 {visible} / {total}', noPolicies: '没有符合当前筛选条件的策略。', confirmDelete: '确定删除此策略并关闭活动会话吗？', policyCreated: '策略已创建。', policyUpdated: '策略已更新。', policyDeleted: '策略已删除。', policyEnabled: '策略已启用。', policyDisabled: '策略已停用。', exportPolicies: '导出', exportCsv: '导出 CSV', importPolicies: '导入', selectVisible: '选择当前结果', selectedPolicies: '已选择 {count} 项', migrateClient: '迁移客户端', bulkCompleted: '批量操作已完成。', importCompleted: '已导入 {count} 条策略。', invalidImport: '策略导入文件无效。', confirmBulkDelete: '确定删除选中的 {count} 条策略并关闭活动会话吗？', trafficControl: '流量控制', trafficControlHelp: '限制来源、新建连接速率、每日流量和 UTC 生效时段。', allowedCidrs: '允许的 CIDR', deniedCidrs: '拒绝的 CIDR', cidrPlaceholder: '每行一个 CIDR，例如 203.0.113.0/24', connectionRate: '每分钟新建连接数', dailyQuota: '每日配额（MiB）', activeWeekdays: 'UTC 生效星期（0-6）', weekdaysPlaceholder: '0,1,2,3,4 表示周一到周五', activeWindow: 'UTC 生效时段', usageToday: '今日已用：{value}', trafficControlSaved: '流量控制已保存。', targetPoolHelp: '多个目标用逗号分隔，使用 @权重 进行加权路由，例如 127.0.0.1:2333@2,127.0.0.1:2444@1。',
          tcpTitle: 'TCP 隧道', tcpSubtitle: '开放一个 TCP 端口，并将每个连接转发到指定客户端。', udpTitle: 'UDP 隧道', udpSubtitle: '通过会话跟踪和带宽控制转发 UDP 数据报。', portsTitle: '端口组', portsSubtitle: '将多个 TCP 或 UDP 端口映射作为一项策略管理。', httpTitle: 'HTTP / HTTPS 路由', httpSubtitle: '按域名转发 HTTP/1.1、HTTP/2 与原生 gRPC，并可自动管理 HTTPS 证书。', httpTransportCapabilities: '公网支持 HTTP/1.1 与 HTTP/2。原生 gRPC 使用复用的 h2c 后端连接池；HTTPS 通过 ALPN 协商 h2。', sniTitle: 'TLS SNI 原样透传', sniSubtitle: '根据 SNI 转发 TLS 连接，不在服务端终止 TLS。', secretTitle: '私密隧道', secretSubtitle: '通过一次性凭据在服务提供端和访问端之间建立私密连接。', socks5Title: 'SOCKS5 代理', socks5Subtitle: '开放带认证的 SOCKS5 TCP 和 UDP 访问。', httpProxyTitle: 'HTTP 正向代理', httpProxySubtitle: '开放带认证的 HTTP 和 CONNECT 代理。', acmeTitle: 'ACME 自动化', acmeSubtitle: '配置 HTTP 路由的证书签发和自动续期。',
          socks5CapabilitiesWithUdp: 'CONNECT、BIND、UDP ASSOCIATE 与 UDP FRAG 当前均可用。', socks5CapabilitiesTcpOnly: 'CONNECT 与 BIND 当前可用；UDP relay 未启用，因此 UDP ASSOCIATE 与 UDP FRAG 不可用。', socks5CapabilitiesPartial: '可用：{available}。不可用或未上报：{unavailable}。',
          client: '客户端', name: '名称', tunnelName: '隧道名称', routeName: '路由名称', proxyName: '代理名称', publicPort: '公网端口', targetAddress: '目标地址', maxConnections: '最大连接数', bandwidthLimit: '带宽上限（B/s）', maxSessions: '最大会话数', idleTimeout: '空闲超时（秒）', protocol: '协议', publicPorts: '公网端口', targetHost: '目标主机', targetPorts: '目标端口', hostname: '域名', tlsMode: 'TLS 模式', tlsDisabled: '停用', tlsAutomatic: '自动 ACME', redirectHttps: '将 HTTP 重定向到 HTTPS', providerClient: '服务提供客户端', allowedVisitor: '允许访问的客户端', anyAuthenticatedClient: '任意已认证客户端', proxyUsername: '代理用户名', optional: '可选', unlimited: '不限速', selectClient: '选择客户端', noClients: '当前没有已注册客户端。',
          createTcp: '新建 TCP 隧道', editTcp: '编辑 TCP 隧道', createUdp: '新建 UDP 隧道', editUdp: '编辑 UDP 隧道', createPorts: '新建端口组', editPorts: '编辑端口组', createHttp: '新建 HTTP 路由', editHttp: '编辑 HTTP 路由', createSni: '新建 SNI 路由', editSni: '编辑 SNI 路由', createSecret: '新建私密隧道', editSecret: '编辑私密隧道', createSocks5: '新建 SOCKS5 代理', editSocks5: '编辑 SOCKS5 代理', createHttpProxy: '新建 HTTP 代理', editHttpProxy: '编辑 HTTP 代理',
          secretCreated: '请立即复制访问密钥，此后不会再次显示：{key}', socks5Created: '请立即复制 SOCKS5 凭据。用户名：{username} 密码：{password}', httpProxyCreated: '请立即复制 HTTP 代理凭据。用户名：{username} 密码：{password}',
          certificate: '证书', certificateDisabled: '已停用', certificatePending: '等待签发', certificateIssuing: '签发中', certificateActive: '有效', certificateRenewing: '续期中', certificateError: '错误', certificateExpired: '已过期', enableAutomaticHttps: '启用 HTTPS', disableHttps: '停用 HTTPS', enableRedirect: '启用跳转', disableRedirect: '停用跳转', issueCertificate: '签发证书', renewCertificate: '立即续期', certificateQueued: '证书任务已加入队列。', tlsUpdated: 'TLS 设置已更新。', routeCreatedTlsFailed: '路由已经创建，但 TLS 设置保存失败。表单现已切换到编辑模式，请修正 TLS 设置后再次保存。',
          acmeEnabled: '启用自动证书管理', acmeEnvironment: '环境', acmeStaging: "Let's Encrypt 测试环境", acmeProduction: "Let's Encrypt 正式环境", acmeCustom: '自定义目录', acmeDirectory: '目录 URL', acmeEmail: '联系邮箱', renewBefore: '提前续期天数', acmeTerms: '我同意证书颁发机构的服务条款', saveAcme: '保存 ACME 设置', acmeSaved: 'ACME 设置已保存。', acmeReady: 'ACME 账户已注册', acmePending: 'ACME 账户尚未注册', acmeOff: 'ACME 自动化已停用',
          p2pFresh: '新鲜', p2pStale: '陈旧', candidates: '候选地址', age: '最后更新时间', noP2pNodes: '当前没有已注册的 P2P 候选地址。', mapping: '映射类型', portMapping: '端口映射', rendezvous: '会合服务', unknown: '未知',
          searchActivity: '搜索操作、对象或详情', category: '分类', allCategories: '全部分类', categoryManagement: '管理操作', categoryPolicy: '策略', categoryClient: '客户端', categoryP2p: 'P2P', categoryCertificate: '证书', loadMore: '加载更多', noActivity: '没有符合当前筛选条件的事件。', action: '操作', subject: '对象', detail: '详情', occurredAt: '发生时间', auditCount: '{visible} 条事件',
          auditLogin: '管理员已登录', auditLoginFailed: '管理员登录失败', auditPasswordChanged: '管理员密码已修改', auditLogout: '管理员已退出', auditClientEnrolled: '客户端已注册', auditPolicyCreated: '策略已创建', auditPolicyUpdated: '策略已更新', auditPolicyDeleted: '策略已删除', auditRegistered: '服务已注册', auditAcmeUpdated: 'ACME 设置已更新', auditCertificateStarted: '证书任务已开始', auditCertificateSucceeded: '证书任务已成功', auditCertificateFailed: '证书任务失败', auditP2pUpdated: 'P2P 候选地址已更新', auditP2pDirect: 'P2P 直连已建立', auditP2pRelay: 'P2P 连接已回退到中继',
          signInFailed: '登录失败，请检查用户名和密码。', signingIn: '正在登录…', changeRequired: '请先修改初始密码，再使用管理控制台。', changingPassword: '正在修改密码…', passwordChanged: '密码已修改。', passwordChangeFailed: '无法修改密码，请使用至少 12 位的新密码。', signedOut: '已退出登录。', sessionExpired: '管理员会话已过期，请重新登录。', requestFailed: '服务端没有响应，请检查服务和网络连接。', statusFailed: '无法加载管理数据。', invalidResponse: '服务端返回了无效响应。',
          configIssueAlert: '{count} 个客户端配置存在问题', certificateExpiredAlert: '{count} 张证书已过期', certificateExpiringAlert: '{count} 张证书将在 30 天内到期', authenticationFailureAlert: '服务启动以来发生 {count} 次认证失败', transportErrorAlert: '服务启动以来发生 {count} 次传输或握手错误',
          accessControl: '访问控制', userManagement: '用户管理', userManagementHelp: '创建账户、分配用户组并控制访问权限。', securitySessions: '安全与会话', securitySessionsHelp: '管理双因素认证、API 凭据和当前登录设备。', newUser: '新建用户', displayName: '显示名称', lastLogin: '最后登录', actions: '操作', sessionId: '会话 ID', createdAt: '创建时间', expiresAt: '到期时间', forcePasswordChange: '下次登录时必须修改密码', resetPassword: '重置密码', revokeSessions: '撤销会话', revoke: '撤销', userFormHelp: '密码至少需要 12 位。', userCreated: '用户已创建。', userUpdated: '用户已更新。', userDeleted: '用户已删除。', passwordReset: '密码已重置。', sessionsRevoked: '会话已撤销。', confirmUserDelete: '确定删除用户 {username} 吗？', confirmRevokeSessions: '确定撤销 {username} 的全部会话吗？', confirmRevokeSession: '确定撤销该会话吗？', never: '从未登录', mustChangePassword: '需要修改密码', currentSession: '当前会话', total: '总计', searchUsers: '搜索用户名或显示名称', allRoles: '全部用户组', userCount: '显示 {visible} / {total}', twoFactorAuth: '双因素认证', totpEnabled: '已启用，登录时需要身份验证器动态验证码。', totpDisabled: '未启用，当前仅使用密码登录。', setupTotp: '开始设置', disableTotp: '关闭', totpSetupHelp: '将设置密钥或 URI 添加到身份验证器，然后输入当前验证码。', totpDisableHelp: '请输入当前动态验证码以关闭双因素认证。', totpSecret: '设置密钥', provisioningUri: '配置 URI', totpEnabledMessage: '双因素认证已启用。', totpDisabledMessage: '双因素认证已关闭。', invalidTotp: '动态验证码无效。', apiTokens: 'API 令牌', apiTokensHelp: '为自动化和外部集成创建限定权限的令牌。', newApiToken: '新建令牌', apiToken: 'API 令牌', apiTokenShownOnce: '该令牌只显示一次，关闭前请复制保存。', scope: '权限范围', scopeRead: '只读', scopeWrite: '读写', scopeAdministrator: '管理员', expiryDays: '有效天数', lastUsed: '最后使用', activeSignIns: '当前登录', apiTokenCreated: 'API 令牌已创建。', apiTokenRevoked: 'API 令牌已撤销。', confirmApiTokenRevoke: '确定撤销 API 令牌 {name} 吗？', noApiTokens: '暂无 API 令牌。',
          clientManagement: '客户端管理', clientManagementHelp: '整理客户端身份、撤销访问并轮换凭据。', searchClients: '搜索名称、分组、标签、平台或 ID', clientGroup: '分组', tags: '标签', tagsPlaceholder: '用逗号分隔，例如 game, home, asia', notes: '备注', platform: '平台', lastSeen: '最后在线', configStatus: '配置状态', editClient: '编辑客户端', rotateToken: '轮换令牌', newClientToken: '新客户端令牌', tokenShownOnce: '该令牌只显示一次，关闭前请更新客户端配置。', clientToken: '客户端令牌', copy: '复制', done: '完成', clientEnabledHelp: '允许该身份认证并接收策略', clientUpdated: '客户端已更新。', clientDeleted: '客户端已删除。', tokenRotated: '客户端令牌已轮换。', tokenCopied: '令牌已复制。', confirmClientDelete: '确定删除离线客户端 {name} 吗？引用它的策略必须先迁移。', confirmTokenRotation: '确定轮换 {name} 的令牌吗？旧令牌会立即失效。', clientCount: '显示 {visible} / {total}', localConfig: '本地配置', reportOnlyConfig: '仅上报', managedConfig: '服务端托管', synchronized: '已同步', conflict: '冲突', applyFailed: '应用失败', unknownConfig: '未知',
          allowedPorts: '允许范围：{ports}', reservedPorts: '保留端口：{ports}', errorUnknownClient: '所选客户端不存在。', errorInvalidName: '名称长度必须为 1 到 80 个字符。', errorInvalidPort: '公网端口不符合服务端策略。{ports}。', errorDuplicatePort: '该公网端口已被占用。', errorInvalidTarget: '请使用有效的 host:port 目标地址。', errorInvalidHostname: '域名格式无效。', errorDuplicateHostname: '该域名已被占用。', errorInvalidLimit: '某项限制参数无效。', errorStorage: '策略存储不可用，请检查数据目录和服务端日志。', errorUnknownPolicy: '策略不存在。', errorInvalidUsername: '代理用户名格式无效。', errorInvalidPortExpression: '请使用单端口、逗号列表或升序范围。', errorPortCountMismatch: '公网端口与目标端口数量必须一致。', errorDuplicatePortInGroup: '端口组内存在重复端口。', errorTooManyMappings: '一个端口组最多包含 256 个映射。', errorAcme: 'ACME 请求失败，请检查设置、DNS 和服务端日志。'
        }
      };

      Object.assign(WORDS.en, {
        metricSloFastBurn: 'SLO fast burn rate',
        metricSloSlowBurn: 'SLO slow burn rate',
        more: 'More',
        moreActions: 'More actions',
        visualStyle: 'Visual style',
        themeModeLabel: 'Brightness mode',
        materialThemeLabel: 'Material theme',
        styleAurora: 'Aurora',
        styleAuroraHelp: 'Layered glass and lake light',
        styleMinimal: 'Minimal',
        styleMinimalHelp: 'Flat, precise and information dense',
        stylePaper: 'Paper',
        stylePaperHelp: 'Soft surfaces and clear boundaries',
        styleNeon: 'Neon',
        styleNeonHelp: 'Deep space and restrained glow',
        styleContrast: 'High contrast',
        styleContrastHelp: 'Strong borders and accessible contrast',
        protocolTrend: 'Protocol trend',
        protocolTrendHelp: 'Traffic, activity and errors for the selected protocol.',
        policyStatusChart: 'Policy status',
        policyStatusChartHelp: 'Current availability and workload distribution.',
        clientStatusOverview: 'Client status overview',
        clientStatusOverviewHelp: 'Availability and configuration state for the filtered clients.',
        clientPlatformChart: 'Platform and configuration',
        clientPlatformChartHelp: 'Platform and managed configuration distribution.',
        loadingHistory: 'Loading history…',
        workload: 'Workload',
        errors: 'Errors',
        platforms: 'Platforms',
        justNow: 'Just now',
        neverSeen: 'Never connected',
        seenAgo: '{time} ago',
        other: 'Other',
        trafficTrendChartLabel: 'Inbound and outbound traffic trend',
        protocolActivityChartLabel: 'Protocol activity bar chart',
        failureOverviewChartLabel: 'Failure overview bar chart',
        protocolTrendChartLabel: 'Protocol traffic, workload and error trend',
        policyStatusChartLabel: 'Policy availability and workload chart',
        clientStatusChartLabel: 'Client availability chart',
        clientPlatformChartLabel: 'Client platform and configuration chart',
        systemManagement: 'System',
        updateCenter: 'Update center',
        updateCenterHelp: 'Inspect signed release status and perform explicitly confirmed server maintenance.',
        serverUpdate: 'Server update',
        serverUpdateHelp: 'Check, verify and schedule a signed stable release.',
        clientUpdate: 'Client update',
        clientUpdateHelp: 'Clients update locally so the server cannot silently replace endpoint binaries.',
        localOnly: 'Local only',
        clientUpdateBoundary: 'Remote client replacement is intentionally unavailable. Run the signed updater on each client host or through your own authorized device-management system.',
        productionSignatureOnly: 'Production signatures only',
        production: 'Production',
        signaturePolicy: 'Signature policy',
        downgradeBlocked: 'Downgrades blocked',
        localConfirmationRequired: 'Local confirmation required',
        checkForUpdates: 'Check for updates',
        downloadUpdate: 'Download and verify',
        applyUpdate: 'Apply update',
        rollbackRecovery: 'Rollback and recovery',
        rollbackRecoveryHelp: 'Database-aware rollback and interrupted-update recovery remain local administrator operations because they can require explicit data-loss consent.',
        installedVersion: 'Installed version',
        targetPlatform: 'Target platform',
        sourceRepository: 'Source repository',
        releaseChannel: 'Release channel',
        updateState: 'Update state',
        latestVersion: 'Latest version',
        signingKey: 'Signing key',
        packageDigest: 'Package SHA-256',
        updateAvailable: 'Update available',
        upToDate: 'Up to date',
        stableChannel: 'Stable',
        updateIdle: 'Idle',
        noUpdateScheduled: 'No update operation has been scheduled.',
        updateBusy: 'In progress',
        updateFailed: 'Failed',
        updateSucceeded: 'Succeeded',
        updateRolledBack: 'Rolled back',
        updateOperationFailed: 'The secure update operation failed. Check the server log and outbound GitHub connectivity.',
        updateChecked: 'Signed release metadata verified.',
        updateDownloaded: 'Update downloaded and verified.',
        updateScheduled: 'Update scheduled. The server will restart and roll back automatically if validation fails.',
        updateApplyResponseInterrupted: 'The connection closed while scheduling the update. Do not retry until the server returns and the persisted update status has been refreshed.',
        confirmDownloadUpdate: 'Download the latest stable server package and verify its signed manifest and SHA-256 digest?',
        confirmApplyUpdate: 'Apply the latest stable server update now? The server will restart. Automatic rollback remains enabled.',
        typeUpdateConfirmation: 'Type {phrase} to continue.',
        updateConfirmationMismatch: 'The confirmation phrase did not match. No update request was sent.',
        updateSecurityCheckFailed: 'The update request did not pass the same-origin session security check. Refresh the page and sign in again.',
        updateUnavailable: 'A persistent LINKLAKE_DATA_DIR is required before server updates can be applied.',
        confirmationProtected: 'Interactive administrator confirmation',
        signedManifestProtected: 'Ed25519 signed manifest',
        rollbackProtected: 'Automatic validation and rollback',
        remoteClientUpdateDisabled: 'Remote client update disabled',
        releaseDetails: 'Release details'
      });

      Object.assign(WORDS.zh, {
        metricSloFastBurn: 'SLO 快速预算燃烧率',
        metricSloSlowBurn: 'SLO 慢速预算燃烧率',
        more: '更多',
        moreActions: '更多操作',
        visualStyle: '视觉风格',
        themeModeLabel: '明暗模式',
        materialThemeLabel: '材质主题',
        styleAurora: '极光湖面',
        styleAuroraHelp: '分层玻璃质感与湖面光晕',
        styleMinimal: '极简海洋',
        styleMinimalHelp: '扁平、精准且信息密度更高',
        stylePaper: '翡翠纸面',
        stylePaperHelp: '柔和表面与清晰边界',
        styleNeon: '霓虹深空',
        styleNeonHelp: '深色空间与克制辉光',
        styleContrast: '高对比度',
        styleContrastHelp: '强化边框与无障碍对比度',
        protocolTrend: '协议趋势',
        protocolTrendHelp: '展示当前协议的流量、活跃负载与错误趋势。',
        policyStatusChart: '策略状态',
        policyStatusChartHelp: '展示当前可用性与工作负载分布。',
        clientStatusOverview: '客户端状态总览',
        clientStatusOverviewHelp: '展示筛选结果中的可用性与配置状态。',
        clientPlatformChart: '平台与配置',
        clientPlatformChartHelp: '展示平台及服务端托管配置的分布。',
        loadingHistory: '正在加载历史指标…',
        workload: '活跃负载',
        errors: '错误',
        platforms: '平台数',
        justNow: '刚刚在线',
        neverSeen: '从未连接',
        seenAgo: '{time}前',
        other: '其他',
        trafficTrendChartLabel: '入站与出站流量趋势图',
        protocolActivityChartLabel: '协议活跃度条形图',
        failureOverviewChartLabel: '故障概览条形图',
        protocolTrendChartLabel: '协议流量、负载与错误趋势图',
        policyStatusChartLabel: '策略可用性与负载图',
        clientStatusChartLabel: '客户端可用性图',
        clientPlatformChartLabel: '客户端平台与配置图',
        systemManagement: '系统',
        updateCenter: '更新中心',
        updateCenterHelp: '查看签名版本状态，并执行需要明确确认的服务端维护操作。',
        serverUpdate: '服务端更新',
        serverUpdateHelp: '检查、校验并调度经过签名的稳定版本。',
        clientUpdate: '客户端更新',
        clientUpdateHelp: '客户端在本机完成更新，服务端不能静默替换端点程序。',
        localOnly: '仅本机',
        clientUpdateBoundary: '当前有意不提供远程替换客户端程序的能力。请在每台客户端主机上运行签名更新器，或使用你已授权的设备管理系统。',
        productionSignatureOnly: '仅信任生产签名',
        production: '生产',
        signaturePolicy: '签名策略',
        downgradeBlocked: '禁止降级',
        localConfirmationRequired: '需要本机确认',
        checkForUpdates: '检查更新',
        downloadUpdate: '下载并校验',
        applyUpdate: '应用更新',
        rollbackRecovery: '回滚与恢复',
        rollbackRecoveryHelp: '数据库感知回滚和中断更新恢复仍由本机管理员执行，因为它们可能需要明确的数据丢失确认。',
        installedVersion: '已安装版本',
        targetPlatform: '目标平台',
        sourceRepository: '来源仓库',
        releaseChannel: '更新通道',
        updateState: '更新状态',
        latestVersion: '最新版本',
        signingKey: '签名密钥',
        packageDigest: '软件包 SHA-256',
        updateAvailable: '有可用更新',
        upToDate: '已是最新版',
        stableChannel: '稳定版',
        updateIdle: '空闲',
        noUpdateScheduled: '当前没有已调度的更新操作。',
        updateBusy: '执行中',
        updateFailed: '失败',
        updateSucceeded: '成功',
        updateRolledBack: '已回滚',
        updateOperationFailed: '安全更新操作失败，请检查服务端日志和 GitHub 出站连接。',
        updateChecked: '签名版本元数据已验证。',
        updateDownloaded: '更新包已下载并通过校验。',
        updateScheduled: '更新已调度。服务端将重启；如果验证失败会自动回滚。',
        updateApplyResponseInterrupted: '调度更新时连接已中断。在服务端恢复且持久化更新状态刷新前，请勿重复提交。',
        confirmDownloadUpdate: '下载最新稳定版服务端软件包，并验证签名清单和 SHA-256 摘要吗？',
        confirmApplyUpdate: '现在应用最新稳定版服务端更新吗？服务端将重启，并保留自动回滚保护。',
        typeUpdateConfirmation: '请输入 {phrase} 以继续。',
        updateConfirmationMismatch: '确认词不匹配，未发送更新请求。',
        updateSecurityCheckFailed: '更新请求未通过同源会话安全检查，请刷新页面并重新登录。',
        updateUnavailable: '应用服务端更新前必须配置持久化的 LINKLAKE_DATA_DIR。',
        confirmationProtected: '交互式管理员确认',
        signedManifestProtected: 'Ed25519 签名清单',
        rollbackProtected: '自动验证与回滚',
        remoteClientUpdateDisabled: '已禁用远程客户端更新',
        releaseDetails: '版本详情'
      });

      const POLICY_TYPES = {
        tcp: {
          resource: 'tcp-tunnels', dataKey: 'tcpPolicies', titleKey: 'tcpTitle', subtitleKey: 'tcpSubtitle', createKey: 'createTcp', editKey: 'editTcp',
          fields: [
            { name: 'client_id', label: 'client', type: 'client', required: true, full: true },
            { name: 'name', label: 'tunnelName', type: 'text', required: true, full: true },
            { name: 'public_port', label: 'publicPort', type: 'number', min: 1, max: 65535, required: true, portProtocol: 'tcp' },
            { name: 'target_addr', label: 'targetAddress', type: 'text', required: true, full: true },
            { name: 'max_connections', label: 'maxConnections', type: 'number', min: 1, max: 1024, required: true, default: 64 },
            { name: 'bandwidth_limit_bps', label: 'bandwidthLimit', type: 'number', min: 1024, max: 1000000000 }
          ]
        },
        udp: {
          resource: 'udp-tunnels', dataKey: 'udpPolicies', titleKey: 'udpTitle', subtitleKey: 'udpSubtitle', createKey: 'createUdp', editKey: 'editUdp',
          fields: [
            { name: 'client_id', label: 'client', type: 'client', required: true, full: true },
            { name: 'name', label: 'tunnelName', type: 'text', required: true, full: true },
            { name: 'public_port', label: 'publicPort', type: 'number', min: 1, max: 65535, required: true, portProtocol: 'udp' },
            { name: 'target_addr', label: 'targetAddress', type: 'text', required: true, full: true },
            { name: 'max_sessions', label: 'maxSessions', type: 'number', min: 1, max: 4096, required: true, default: 256 },
            { name: 'session_idle_timeout_seconds', label: 'idleTimeout', type: 'number', min: 30, max: 3600, required: true, default: 120 },
            { name: 'bandwidth_limit_bps', label: 'bandwidthLimit', type: 'number', min: 1024, max: 1000000000 }
          ]
        },
        ports: {
          resource: 'port-groups', dataKey: 'portGroups', titleKey: 'portsTitle', subtitleKey: 'portsSubtitle', createKey: 'createPorts', editKey: 'editPorts',
          fields: [
            { name: 'client_id', label: 'client', type: 'client', required: true, full: true },
            { name: 'name', label: 'tunnelName', type: 'text', required: true, full: true },
            { name: 'protocol', label: 'protocol', type: 'select', options: [{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }], required: true, default: 'tcp' },
            { name: 'public_ports', label: 'publicPorts', type: 'text', required: true, full: true, portProtocolField: 'protocol' },
            { name: 'target_host', label: 'targetHost', type: 'text', required: true },
            { name: 'target_ports', label: 'targetPorts', type: 'text', required: true },
            { name: 'max_connections', label: 'maxConnections', type: 'number', min: 1, max: 1024, default: 64, when: { field: 'protocol', value: 'tcp' } },
            { name: 'max_sessions', label: 'maxSessions', type: 'number', min: 1, max: 4096, default: 256, when: { field: 'protocol', value: 'udp' } },
            { name: 'session_idle_timeout_seconds', label: 'idleTimeout', type: 'number', min: 30, max: 3600, default: 120, when: { field: 'protocol', value: 'udp' } },
            { name: 'bandwidth_limit_bps', label: 'bandwidthLimit', type: 'number', min: 1024, max: 1000000000 }
          ]
        },
        http: {
          resource: 'http-routes', dataKey: 'httpRoutes', titleKey: 'httpTitle', subtitleKey: 'httpSubtitle', createKey: 'createHttp', editKey: 'editHttp',
          fields: [
            { name: 'client_id', label: 'client', type: 'client', required: true, full: true },
            { name: 'name', label: 'routeName', type: 'text', required: true, full: true },
            { name: 'hostname', label: 'hostname', type: 'text', required: true, full: true },
            { name: 'target_addr', label: 'targetAddress', type: 'text', required: true, full: true },
            { name: 'max_connections', label: 'maxConnections', type: 'number', min: 1, max: 1024, required: true, default: 64 },
            { name: 'tls_mode', label: 'tlsMode', type: 'select', options: [{ value: 'disabled', labelKey: 'tlsDisabled' }, { value: 'acme', labelKey: 'tlsAutomatic' }], default: 'disabled' },
            { name: 'redirect_http_to_https', label: 'redirectHttps', type: 'checkbox', full: true, when: { field: 'tls_mode', value: 'acme' } }
          ]
        },
        sni: {
          resource: 'sni-routes', dataKey: 'sniRoutes', titleKey: 'sniTitle', subtitleKey: 'sniSubtitle', createKey: 'createSni', editKey: 'editSni',
          fields: [
            { name: 'client_id', label: 'client', type: 'client', required: true, full: true },
            { name: 'name', label: 'routeName', type: 'text', required: true, full: true },
            { name: 'hostname', label: 'hostname', type: 'text', required: true, full: true },
            { name: 'target_addr', label: 'targetAddress', type: 'text', required: true, full: true },
            { name: 'max_connections', label: 'maxConnections', type: 'number', min: 1, max: 1024, required: true, default: 64 },
            { name: 'bandwidth_limit_bps', label: 'bandwidthLimit', type: 'number', min: 1024, max: 1000000000 }
          ]
        },
        secret: {
          resource: 'secret-tunnels', dataKey: 'secretPolicies', titleKey: 'secretTitle', subtitleKey: 'secretSubtitle', createKey: 'createSecret', editKey: 'editSecret',
          fields: [
            { name: 'provider_client_id', label: 'providerClient', type: 'client', required: true, full: true },
            { name: 'allowed_client_id', label: 'allowedVisitor', type: 'optionalClient', full: true },
            { name: 'name', label: 'tunnelName', type: 'text', required: true, full: true },
            { name: 'target_addr', label: 'targetAddress', type: 'text', required: true, full: true },
            { name: 'max_connections', label: 'maxConnections', type: 'number', min: 1, max: 1024, required: true, default: 32 },
            { name: 'bandwidth_limit_bps', label: 'bandwidthLimit', type: 'number', min: 1024, max: 1000000000 }
          ]
        },
        socks5: {
          resource: 'socks5-proxies', dataKey: 'socks5Policies', titleKey: 'socks5Title', subtitleKey: 'socks5Subtitle', createKey: 'createSocks5', editKey: 'editSocks5',
          fields: [
            { name: 'client_id', label: 'client', type: 'client', required: true, full: true },
            { name: 'name', label: 'proxyName', type: 'text', required: true, full: true },
            { name: 'public_port', label: 'publicPort', type: 'number', min: 1, max: 65535, required: true, portProtocol: 'tcp' },
            { name: 'username', label: 'proxyUsername', type: 'text', required: true },
            { name: 'max_connections', label: 'maxConnections', type: 'number', min: 1, max: 1024, required: true, default: 64 },
            { name: 'bandwidth_limit_bps', label: 'bandwidthLimit', type: 'number', min: 1024, max: 1000000000 }
          ]
        },
        'http-proxy': {
          resource: 'http-proxies', dataKey: 'httpProxyPolicies', titleKey: 'httpProxyTitle', subtitleKey: 'httpProxySubtitle', createKey: 'createHttpProxy', editKey: 'editHttpProxy',
          fields: [
            { name: 'client_id', label: 'client', type: 'client', required: true, full: true },
            { name: 'name', label: 'proxyName', type: 'text', required: true, full: true },
            { name: 'public_port', label: 'publicPort', type: 'number', min: 1, max: 65535, required: true, portProtocol: 'tcp' },
            { name: 'username', label: 'proxyUsername', type: 'text', required: true },
            { name: 'max_connections', label: 'maxConnections', type: 'number', min: 1, max: 1024, required: true, default: 64 },
            { name: 'bandwidth_limit_bps', label: 'bandwidthLimit', type: 'number', min: 1024, max: 1000000000 }
          ]
        }
      };

      const state = {
        language: safeStorageGet('linklake-language', navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'),
        identity: null,
        dashboard: null,
        route: { view: 'overview', service: 'tcp' },
        refreshTimer: null,
        loading: false,
        pendingLoad: false,
        pendingForceHistory: false,
        trafficHistory: [],
        trendRange: '1h',
        serviceTrafficHistory: [],
        serviceHistoryMeta: null,
        serviceTrendRange: '1h',
        serviceHistoryProtocol: 'total',
        historyCache: new Map(),
        historyRequestGeneration: 0,
        historyActiveKey: null,
        historyPromise: null,
        lastTrafficTotals: null,
        drawer: { open: false, type: null, id: null, dirty: false, values: null },
        serviceSearch: '',
        serviceStatus: 'all',
        visibleServicePolicies: [],
        selectedPolicies: new Set(),
        auditLimit: 20,
        auditSearch: '',
        auditCategory: 'all',
        expandedAudit: new Set(),
        userSearch: '',
        userRole: 'all',
        clientSearch: '',
        clientStatus: 'all',
        visibleClients: [],
        clientEditorId: null,
        globalSearchTimer: null,
        users: [],
        sessions: [],
        apiTokens: [],
        fleetEditorId: null,
        trafficEditor: null,
        totpMode: 'enable',
        userEditor: { mode: 'create', username: null },
        resetUsername: null,
        alertEditorId: null,
        serverUpdateCheck: null,
        toastTimer: null,
        activeControllers: new Set()
      };

      const elements = Object.fromEntries([
        'theme-color', 'appearance-button', 'appearance-popover', 'language', 'utility-session', 'account-shell', 'global-search-shell', 'global-search', 'global-search-results', 'login-shell', 'login', 'username', 'password', 'login-totp-label', 'login-totp', 'initial-password-form', 'initial-new-password', 'initial-confirm-password', 'workspace', 'workspace-title', 'workspace-subtitle', 'workspace-service-actions', 'workspace-fleet-actions', 'workspace-user-actions', 'workspace-alert-actions', 'last-refresh', 'refresh', 'account-button', 'account-avatar', 'account-name', 'account-menu', 'account-menu-name', 'account-menu-role', 'account-menu-expiry', 'account-password', 'account-security', 'logout',
        'overview-view', 'overview-kpis', 'traffic-chart', 'traffic-tooltip', 'traffic-chart-summary', 'export-metrics', 'service-health-summary', 'overview-alert-panel', 'overview-alerts', 'overview-alert-more',
        'metrics-view', 'metrics-kpis', 'activity-chart', 'failure-chart', 'tcp-metric-panel', 'udp-metric-panel', 'proxy-metric-panel', 'web-metric-panel', 'network-health-panel', 'system-metric-panel',
        'services-view', 'service-insights', 'service-trend-title', 'service-insight-kpis', 'service-trend-chart', 'service-status-chart', 'new-policy', 'export-policies', 'import-policies', 'import-policies-file', 'service-toolbar', 'service-search', 'service-status-filter', 'service-count', 'service-bulk-toolbar', 'select-visible-policies', 'selected-policy-count', 'bulk-enable-policies', 'bulk-disable-policies', 'bulk-client-target', 'bulk-migrate-policies', 'bulk-delete-policies', 'service-list', 'acme-page',
        'p2p-view', 'p2p-list', 'fleet-view', 'new-fleet-peer', 'preview-fleet-sync', 'apply-fleet-sync', 'fleet-summary', 'fleet-conflicts', 'fleet-list', 'clients-view', 'client-insight-kpis', 'client-status-chart', 'client-platform-chart', 'client-search', 'client-status-filter', 'client-count', 'clients-list', 'users-view', 'new-user', 'user-search', 'user-role-filter', 'user-count', 'users-list', 'sessions-view', 'totp-status', 'totp-action', 'new-api-token', 'api-tokens-list', 'sessions-list', 'updates-view', 'update-kpis', 'server-update-state', 'server-update-details', 'server-update-security', 'check-server-update', 'download-server-update', 'apply-server-update', 'server-update-release', 'alerts-view', 'new-alert-rule', 'alert-channels', 'alert-events', 'alert-rules', 'activity-view', 'audit-search', 'audit-category', 'audit-count', 'audit-list', 'audit-load-more', 'export-audit',
        'drawer-backdrop', 'policy-drawer', 'drawer-title', 'drawer-subtitle', 'drawer-close', 'drawer-cancel', 'policy-form', 'policy-fields', 'drawer-submit',
        'password-modal', 'password-modal-close', 'password-form', 'account-new-password', 'account-confirm-password', 'password-cancel',
        'user-modal', 'user-modal-title', 'user-modal-help', 'user-modal-close', 'user-form', 'user-username', 'user-display-name', 'user-role', 'user-password-label', 'user-password', 'user-enabled-label', 'user-enabled', 'user-force-change-label', 'user-force-change', 'user-cancel',
        'reset-password-modal', 'reset-password-close', 'reset-password-form', 'reset-password-value', 'reset-force-change', 'reset-password-cancel',
        'totp-modal', 'totp-modal-title', 'totp-modal-help', 'totp-modal-close', 'totp-setup-fields', 'totp-secret', 'totp-uri', 'totp-form', 'totp-code', 'totp-cancel', 'totp-submit',
        'api-token-modal', 'api-token-title', 'api-token-close', 'api-token-form', 'api-token-fields', 'api-token-name', 'api-token-scope', 'api-token-expiry', 'api-token-value-label', 'api-token-value', 'api-token-cancel', 'api-token-submit', 'api-token-copy',
        'fleet-modal', 'fleet-modal-title', 'fleet-modal-close', 'fleet-form', 'fleet-name', 'fleet-url', 'fleet-region', 'fleet-token-env', 'fleet-priority', 'fleet-weight', 'fleet-enabled', 'fleet-cancel',
        'traffic-control-modal', 'traffic-control-title', 'traffic-control-close', 'traffic-control-form', 'traffic-allowed', 'traffic-denied', 'traffic-rate', 'traffic-quota', 'traffic-weekdays', 'traffic-start', 'traffic-end', 'traffic-enabled', 'traffic-usage', 'traffic-control-cancel',
        'client-modal', 'client-modal-title', 'client-modal-id', 'client-modal-close', 'client-form', 'client-name', 'client-group', 'client-tags', 'client-notes', 'client-enabled', 'client-cancel', 'client-token-modal', 'client-token-close', 'client-token-value', 'client-token-copy', 'client-token-done', 'alert-rule-modal', 'alert-rule-title', 'alert-rule-close', 'alert-rule-form', 'alert-rule-name', 'alert-rule-metric', 'alert-rule-comparator', 'alert-rule-threshold', 'alert-rule-target', 'alert-rule-window', 'alert-rule-cooldown', 'alert-rule-severity', 'alert-rule-enabled', 'alert-rule-webhook', 'alert-rule-email', 'alert-rule-cancel', 'toast'
      ].map(id => [id.replaceAll('-', '_'), document.getElementById(id)]));

      const systemTheme = matchMedia('(prefers-color-scheme: dark)');
      let chartRenderFrame = null;
      let chartResizeObserver = null;
      let pixelRatioMedia = null;
      const observedChartSizes = new WeakMap();
      const acmeDirectories = {
        production: 'https://acme-v02.api.letsencrypt.org/directory',
        staging: 'https://acme-staging-v02.api.letsencrypt.org/directory'
      };

      function t(key, values = {}) {
        const template = WORDS[state.language][key] ?? WORDS.en[key] ?? key;
        return Object.entries(values).reduce((message, [name, value]) => message.replaceAll(`{${name}}`, String(value)), template);
      }

      function applyLanguage() {
        document.documentElement.lang = state.language === 'zh' ? 'zh-CN' : 'en';
        document.title = t('title');
        elements.language.textContent = state.language === 'zh' ? 'EN' : 'ZH';
        elements.language.setAttribute('aria-label', t('language'));
        document.querySelectorAll('[data-i18n]').forEach(node => { node.textContent = t(node.dataset.i18n); });
        document.querySelectorAll('[data-placeholder]').forEach(node => { node.placeholder = t(node.dataset.placeholder); });
        document.querySelectorAll('[data-i18n-aria-label]').forEach(node => { node.setAttribute('aria-label', t(node.dataset.i18nAriaLabel)); });
        updateIdentityUi();
        renderRoute();
        if (state.drawer.open) refreshDrawerLanguage();
      }

      function resolvedScheme(mode = document.documentElement.dataset.themeMode) {
        return mode === 'system' ? (systemTheme.matches ? 'dark' : 'light') : mode;
      }

      function applyTheme(mode, palette, persist = true) {
        const root = document.documentElement;
        root.dataset.themeMode = mode;
        root.dataset.scheme = resolvedScheme(mode);
        root.dataset.palette = palette;
        elements.theme_color.content = getComputedStyle(root).getPropertyValue('--bg').trim();
        if (persist) {
          safeStorageSet('linklake-theme-mode', mode);
          safeStorageSet('linklake-palette', palette);
        }
        updateThemeButtons();
        scheduleResponsiveRender();
      }

      function updateThemeButtons() {
        const root = document.documentElement;
        document.querySelectorAll('[data-theme-choice]').forEach(button => button.classList.toggle('active', button.dataset.themeChoice === root.dataset.themeMode));
        document.querySelectorAll('[data-palette-choice]').forEach(button => button.classList.toggle('active', button.dataset.paletteChoice === root.dataset.palette));
      }

      function positionPopover(popover, button) {
        const margin = 14;
        const trigger = button.getBoundingClientRect();
        const top = Math.ceil(trigger.bottom + 8);
        popover.style.top = `${top}px`;
        popover.style.right = `${Math.max(margin, Math.ceil(window.innerWidth - trigger.right))}px`;
        popover.style.maxHeight = `${Math.max(160, Math.floor(window.innerHeight - top - margin))}px`;
        popover.style.overflowY = 'auto';
      }

      function togglePopover(popover, button, force) {
        const show = force ?? popover.classList.contains('hidden');
        popover.classList.toggle('hidden', !show);
        if (button) button.setAttribute('aria-expanded', String(show));
        if (show && button && popover.classList.contains('popover')) positionPopover(popover, button);
      }

      function formatBytes(value) {
        const number = Number(value) || 0;
        if (number < 1024) return `${Math.round(number)} B`;
        if (number < 1048576) return `${(number / 1024).toFixed(1)} KiB`;
        if (number < 1073741824) return `${(number / 1048576).toFixed(1)} MiB`;
        return `${(number / 1073741824).toFixed(2)} GiB`;
      }

      function formatRate(value) { return `${formatBytes(value)}/s`; }
      function formatTimestamp(value) { return value ? new Date(Number(value) * 1000).toLocaleString(state.language === 'zh' ? 'zh-CN' : 'en') : '—'; }
      function formatDuration(seconds) {
        const value = Math.max(0, Number(seconds) || 0);
        const days = Math.floor(value / 86400);
        const hours = Math.floor((value % 86400) / 3600);
        const minutes = Math.floor((value % 3600) / 60);
        if (days) return `${days}d ${hours}h`;
        if (hours) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
      }

      function metric(key) {
        const value = Number(state.dashboard?.metrics?.[key] ?? 0);
        return Number.isFinite(value) ? value : 0;
      }

      function sumMetrics(keys) { return keys.reduce((total, key) => total + metric(key), 0); }
      function isPolicyOnline(policy) { return Boolean(policy?.online || Number(policy?.online_mappings || 0) > 0); }
      function clientName(id) { return state.dashboard?.clients?.find(client => client.client_id === id)?.name || id || '—'; }

      function showToast(message, error = false, timeout = 5000) {
        clearTimeout(state.toastTimer);
        elements.toast.textContent = message;
        elements.toast.classList.toggle('error', error);
        elements.toast.classList.remove('hidden');
        if (timeout) state.toastTimer = setTimeout(() => elements.toast.classList.add('hidden'), timeout);
      }

      function readApiErrorCode(code, fallback = 'requestFailed') {
        if (code === 'invalid_public_port') return t('errorInvalidPort', { ports: portPolicyDescription() });
        const map = {
          unknown_client: 'errorUnknownClient', invalid_name: 'errorInvalidName', invalid_public_port: 'errorInvalidPort', duplicate_public_port: 'errorDuplicatePort', duplicate_tcp_public_port: 'errorDuplicatePort', invalid_target: 'errorInvalidTarget', invalid_hostname: 'errorInvalidHostname', duplicate_hostname: 'errorDuplicateHostname', duplicate_sni_hostname: 'errorDuplicateHostname', invalid_connection_limit: 'errorInvalidLimit', invalid_session_limit: 'errorInvalidLimit', invalid_idle_timeout: 'errorInvalidLimit', invalid_bandwidth_limit: 'errorInvalidLimit', invalid_socks5_username: 'errorInvalidUsername', invalid_http_proxy_username: 'errorInvalidUsername', invalid_port_expression: 'errorInvalidPortExpression', port_count_mismatch: 'errorPortCountMismatch', duplicate_port_in_group: 'errorDuplicatePortInGroup', too_many_port_mappings: 'errorTooManyMappings', unknown_policy: 'errorUnknownPolicy', unknown_udp_tunnel: 'errorUnknownPolicy', unknown_port_group: 'errorUnknownPolicy', unknown_http_route: 'errorUnknownPolicy', unknown_sni_route: 'errorUnknownPolicy', unknown_secret_tunnel: 'errorUnknownPolicy', unknown_socks5_proxy: 'errorUnknownPolicy', unknown_http_proxy: 'errorUnknownPolicy', tcp_policy_storage_error: 'errorStorage', udp_policy_storage_error: 'errorStorage', port_group_policy_storage_error: 'errorStorage', http_route_policy_storage_error: 'errorStorage', sni_route_policy_storage_error: 'errorStorage', secret_policy_storage_error: 'errorStorage', socks5_policy_storage_error: 'errorStorage', http_proxy_policy_storage_error: 'errorStorage', server_update_busy: 'updateBusy', server_update_unavailable: 'updateUnavailable', server_update_failed: 'updateOperationFailed', update_confirmation_required: 'localConfirmationRequired', session_authentication_required: 'updateSecurityCheckFailed', csrf_check_failed: 'updateSecurityCheckFailed', update_origin_check_failed: 'updateSecurityCheckFailed'
        };
        if (String(code || '').includes('acme') || String(code || '').includes('certificate') || String(code || '').includes('tls_')) return t('errorAcme');
        return t(map[code] || fallback);
      }

      async function responseError(response, fallback = 'requestFailed') {
        try { return readApiErrorCode((await response.json()).code, fallback); }
        catch (_) { return t(fallback); }
      }

      function setBusy(button, busy, key = 'saving') {
        if (!button) return;
        if (busy) {
          button.dataset.originalText = button.textContent;
          button.textContent = t(key);
        } else if (button.dataset.originalText) {
          button.textContent = button.dataset.originalText;
          delete button.dataset.originalText;
        }
        button.disabled = busy;
      }

      async function apiFetch(url, options = {}) {
        const { skipAuthReset = false, timeoutMs = 15000, scope = 'default', ...request } = options;
        request.headers = new Headers(request.headers || {});
        if (!['GET', 'HEAD', 'OPTIONS'].includes(String(request.method || 'GET').toUpperCase())) request.headers.set('X-LinkLake-CSRF', '1');
        const controller = new AbortController();
        controller.linklakeScope = scope;
        state.activeControllers.add(controller);
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', ...request, signal: controller.signal });
          if (response.status === 401 && !skipAuthReset && state.identity) resetForExpiredSession();
          return response;
        } finally { clearTimeout(timeout); state.activeControllers.delete(controller); }
      }

      function abortActiveRequests(scope = null) {
        state.activeControllers.forEach(controller => {
          if (!scope || controller.linklakeScope === scope) {
            controller.abort();
            state.activeControllers.delete(controller);
          }
        });
      }

      function parseRoute() {
        const parts = (location.hash || '#/overview').replace(/^#\/?/, '').split('/').filter(Boolean);
        if (parts[0] === 'services') {
          const requested = parts[1] || 'tcp';
          if (POLICY_TYPES[requested] || requested === 'acme') return { view: 'services', service: requested };
          history.replaceState(null, '', '#/overview');
          return { view: 'overview', service: state.route.service || 'tcp' };
        }
        if (['users', 'sessions', 'fleet', 'updates'].includes(parts[0]) && state.identity?.role !== 'administrator') {
          history.replaceState(null, '', '#/overview');
          return { view: 'overview', service: state.route.service || 'tcp' };
        }
        if (['overview', 'metrics', 'clients', 'p2p', 'fleet', 'users', 'sessions', 'updates', 'alerts', 'activity'].includes(parts[0])) return { view: parts[0], service: state.route.service || 'tcp' };
        history.replaceState(null, '', '#/overview');
        return { view: 'overview', service: state.route.service || 'tcp' };
      }

      function routeCopy(route = state.route) {
        if (route.view === 'services') {
          if (route.service === 'acme') return [t('acmeTitle'), t('acmeSubtitle')];
          const schema = POLICY_TYPES[route.service] || POLICY_TYPES.tcp;
          return [t(schema.titleKey), t(schema.subtitleKey)];
        }
        const map = {
          overview: [t('overview'), t('overviewSubtitle')],
          metrics: [t('metrics'), t('metricsSubtitle')],
          clients: [t('clientManagement'), t('clientManagementHelp')],
          p2p: [t('p2p'), t('p2pSubtitle')],
          fleet: [t('fleet'), t('fleetHelp')],
          users: [t('userManagement'), t('userManagementHelp')],
          sessions: [t('securitySessions'), t('securitySessionsHelp')],
          updates: [t('updateCenter'), t('updateCenterHelp')],
          alerts: [t('alertManagement'), t('alertManagementHelp')],
          activity: [t('activity'), t('activitySubtitle')]
        };
        return map[route.view] || map.overview;
      }

      function renderRoute() {
        state.route = parseRoute();
        const [title, subtitle] = routeCopy();
        elements.workspace_title.textContent = title;
        elements.workspace_subtitle.textContent = subtitle;
        const views = { overview: elements.overview_view, metrics: elements.metrics_view, services: elements.services_view, clients: elements.clients_view, p2p: elements.p2p_view, fleet: elements.fleet_view, users: elements.users_view, sessions: elements.sessions_view, updates: elements.updates_view, alerts: elements.alerts_view, activity: elements.activity_view };
        Object.entries(views).forEach(([name, element]) => element.classList.toggle('hidden', name !== state.route.view));
        elements.workspace_service_actions.classList.toggle('hidden', state.route.view !== 'services' || state.route.service === 'acme');
        elements.workspace_fleet_actions.classList.toggle('hidden', state.route.view !== 'fleet');
        elements.workspace_user_actions.classList.toggle('hidden', state.route.view !== 'users');
        elements.workspace_alert_actions.classList.toggle('hidden', state.route.view !== 'alerts' || state.identity?.role === 'auditor');
        document.querySelectorAll('[data-route-prefix]').forEach(link => link.classList.toggle('active', link.dataset.routePrefix === state.route.view));
        document.querySelectorAll('[data-service-route]').forEach(link => link.classList.toggle('active', state.route.view === 'services' && link.dataset.serviceRoute === state.route.service));
        if (!state.dashboard) {
          scheduleResponsiveRender();
          return;
        }
        if (state.route.view === 'overview') renderOverview();
        else if (state.route.view === 'metrics') renderMetrics();
        else if (state.route.view === 'services') renderServices();
        else if (state.route.view === 'clients') renderClients();
        else if (state.route.view === 'p2p') renderP2p();
        else if (state.route.view === 'fleet') renderFleet();
        else if (state.route.view === 'users') renderUsers();
        else if (state.route.view === 'sessions') renderSessions();
        else if (state.route.view === 'updates') renderUpdateCenter();
        else if (state.route.view === 'alerts') renderAlerts();
        else renderAudit();
        scheduleResponsiveRender();
      }

      function updateIdentityUi() {
        if (!state.identity) return;
        const username = state.identity.username || 'admin';
        const displayName = state.identity.display_name || username;
        const roleKey = { administrator: 'roleAdministrator', operator: 'roleOperator', auditor: 'roleAuditor' }[state.identity.role] || 'roleAuditor';
        elements.account_name.textContent = displayName;
        elements.account_avatar.textContent = displayName.slice(0, 1).toUpperCase();
        elements.account_menu_name.textContent = `${displayName} (${username})`;
        elements.account_menu_role.textContent = `${t(roleKey)} · ${t('authenticationSession')}`;
        elements.account_menu_expiry.textContent = t('sessionExpires', { time: formatTimestamp(state.identity.expires_unix_seconds) });
        document.querySelectorAll('.admin-only').forEach(element => element.classList.toggle('hidden', state.identity.role !== 'administrator'));
        document.querySelectorAll('[data-action="new-policy"], [data-action="edit-policy"], [data-action="toggle-policy"], [data-action="delete-policy"]').forEach(element => element.classList.toggle('hidden', state.identity.role === 'auditor'));
      }

      function createKpi(value, label, detail = '') {
        const card = document.createElement('article');
        card.className = 'kpi-card';
        const strong = document.createElement('strong');
        const span = document.createElement('span');
        strong.textContent = value;
        span.textContent = label;
        card.append(strong, span);
        if (detail) {
          const small = document.createElement('small');
          small.textContent = detail;
          card.append(small);
        }
        return card;
      }

      function createInsightKpi(value, label) {
        const card = document.createElement('article');
        card.className = 'insight-kpi';
        const strong = document.createElement('strong'); strong.textContent = value;
        const span = document.createElement('span'); span.textContent = label;
        card.append(strong, span);
        return card;
      }

      function createSummary(label, value, detail = '') {
        const row = document.createElement('div');
        row.className = 'summary-row';
        const name = document.createElement('strong');
        const current = document.createElement('span');
        const extra = document.createElement('span');
        name.textContent = label;
        current.className = 'value';
        current.textContent = value;
        extra.className = 'detail';
        extra.textContent = detail;
        row.append(name, current, extra);
        return row;
      }

      function createHealthSummary(label, list) {
        const online = list.filter(isPolicyOnline).length;
        const enabled = list.filter(policy => policy.enabled).length;
        const counters = [
          ['online', online, t('online')],
          ['offline', Math.max(0, enabled - online), t('offline')],
          ['disabled', list.length - enabled, t('disabled')],
          ['total', list.length, t('total')]
        ];
        const row = document.createElement('div');
        row.className = 'summary-row';
        row.style.gridTemplateColumns = 'minmax(105px, 1fr) auto';
        const name = document.createElement('strong'); name.textContent = label;
        const values = document.createElement('div'); values.className = 'health-counters';
        counters.forEach(([className, value, text]) => {
          const item = document.createElement('span'); item.className = `health-counter ${className}`;
          const strong = document.createElement('strong'); strong.textContent = value;
          const label = document.createElement('span'); label.textContent = text;
          item.append(strong, label); values.append(item);
        });
        row.append(name, values);
        return row;
      }

      function currentTrafficPoint() {
        return state.trafficHistory.at(-1) || { inbound_bps: 0, outbound_bps: 0, active_connections: 0, active_sessions: 0, requests_per_second: 0, errors_per_second: 0 };
      }

      function aggregateTraffic() {
        return {
          inbound: sumMetrics(['tcp_bytes_from_public', 'udp_bytes_from_public', 'http_bytes_from_public', 'sni_bytes_from_public', 'socks5_bytes_from_public', 'socks5_udp_bytes_from_public', 'http_proxy_bytes_from_public']),
          outbound: sumMetrics(['tcp_bytes_to_public', 'udp_bytes_to_public', 'http_bytes_to_public', 'sni_bytes_to_public', 'socks5_bytes_to_public', 'socks5_udp_bytes_to_public', 'http_proxy_bytes_to_public'])
        };
      }

      function allPolicies() {
        const dashboard = state.dashboard;
        return [...dashboard.tcpPolicies, ...dashboard.udpPolicies, ...dashboard.portGroups, ...dashboard.httpRoutes, ...dashboard.sniRoutes, ...dashboard.secretPolicies, ...dashboard.socks5Policies, ...dashboard.httpProxyPolicies];
      }

      function renderOverview() {
        const dashboard = state.dashboard;
        const policies = allPolicies();
        const online = policies.filter(isPolicyOnline).length;
        const point = currentTrafficPoint();
        const configIssues = dashboard.clients.filter(client => client.config_sync_status === 'conflict' || client.config_sync_status === 'apply_failed').length;
        const traffic = aggregateTraffic();
        elements.overview_kpis.replaceChildren(
          createKpi(String(online), t('forwardingServices'), `${policies.length} ${t('total').toLowerCase()}`),
          createKpi(String(dashboard.clients.length), t('clients'), configIssues ? t('configIssues') : ''),
          createKpi(String(Number(point.active_connections || 0) + Number(point.active_sessions || 0)), t('activeSessions')),
          createKpi(`${formatRate(point.inbound_bps)} / ${formatRate(point.outbound_bps)}`, `${t('inbound')} / ${t('outbound')}`),
          createKpi(`${formatBytes(traffic.inbound)} / ${formatBytes(traffic.outbound)}`, t('totalTraffic'))
        );

        const protocolGroups = [
          [t('tcpMetrics'), [...dashboard.tcpPolicies, ...dashboard.portGroups.filter(policy => policy.protocol === 'tcp')]],
          [t('udpMetrics'), [...dashboard.udpPolicies, ...dashboard.portGroups.filter(policy => policy.protocol === 'udp')]],
          [t('webMetrics'), [...dashboard.httpRoutes, ...dashboard.sniRoutes]],
          [t('proxyMetrics'), [...dashboard.socks5Policies, ...dashboard.httpProxyPolicies]],
          [t('secretTitle'), dashboard.secretPolicies]
        ];
        elements.service_health_summary.replaceChildren(...protocolGroups.map(([name, list]) => createHealthSummary(name, list)));

        const alertValues = [...(dashboard.alertEvents || [])]
          .sort((left, right) => Number(right.updated_unix_seconds || 0) - Number(left.updated_unix_seconds || 0))
          .map(event => `${alertSeverityText(event.severity)} · ${event.rule_name} · ${event.subject}: ${event.message}`);
        if (configIssues) alertValues.push(t('configIssueAlert', { count: configIssues }));
        elements.overview_alerts.replaceChildren();
        elements.overview_alert_panel.classList.toggle('hidden', !alertValues.length);
        elements.overview_alert_more.classList.remove('hidden');
        alertValues.slice(0, 5).forEach(value => {
          const alert = document.createElement('div');
          alert.className = 'alert-item';
          alert.textContent = value;
          elements.overview_alerts.append(alert);
        });
        drawTrafficChart();
      }

      function canvasSetup(canvas) {
        if (!canvas || canvas.offsetParent === null) return null;
        const rect = canvas.getBoundingClientRect();
        const ratio = Math.max(1, Math.min(window.devicePixelRatio || 1, 3));
        const width = Math.max(1, Math.round(rect.width));
        const height = Math.max(1, Math.round(rect.height));
        if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
          canvas.width = Math.round(width * ratio);
          canvas.height = Math.round(height * ratio);
        }
        const context = canvas.getContext('2d');
        context.setTransform(ratio, 0, 0, ratio, 0, 0);
        context.clearRect(0, 0, width, height);
        return { context, width, height };
      }

      function cssColor(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
      function cssNumber(name, fallback) {
        const value = Number.parseFloat(cssColor(name));
        return Number.isFinite(value) ? value : fallback;
      }
      function cssDash(name) {
        const values = cssColor(name).split(/\s+/).map(Number).filter(value => Number.isFinite(value) && value > 0);
        return values.length ? values : [];
      }

      function niceMaximum(value) {
        if (!value) return 1;
        const power = 10 ** Math.floor(Math.log10(value));
        const normalized = value / power;
        const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
        return step * power;
      }

      function drawTrafficChart() {
        const setup = canvasSetup(elements.traffic_chart);
        if (!setup) return;
        const { context, width, height } = setup;
        const points = state.trafficHistory;
        const left = 48, right = 14, top = 25, bottom = 28;
        const plotWidth = Math.max(1, width - left - right);
        const plotHeight = Math.max(1, height - top - bottom);
        const grid = cssColor('--chart-grid');
        const label = cssColor('--chart-label');
        const inboundColor = cssColor('--accent');
        const outboundColor = cssColor('--primary');
        context.font = '10px "Segoe UI", sans-serif';
        context.strokeStyle = grid;
        context.fillStyle = label;
        context.lineWidth = 1;
        context.setLineDash(cssDash('--chart-grid-dash'));
        const observedMaximum = Math.max(0, ...points.flatMap(point => [Number(point.inbound_bps) || 0, Number(point.outbound_bps) || 0]));
        if (points.length < 2 || observedMaximum === 0) {
          context.strokeStyle = grid;
          context.beginPath(); context.moveTo(left, top + plotHeight); context.lineTo(width - right, top + plotHeight); context.stroke();
          context.fillStyle = label;
          context.fillText('0 B/s', 7, top + plotHeight + 3);
          const message = points.length < 2 ? t('noTrendData') : t('noTrafficRange');
          const messageWidth = context.measureText(message).width;
          context.fillText(message, Math.max(left, left + plotWidth / 2 - messageWidth / 2), top + plotHeight / 2);
          elements.traffic_chart_summary.textContent = message;
          return;
        }
        const maximum = niceMaximum(observedMaximum);
        for (let index = 0; index <= 4; index += 1) {
          const y = top + (plotHeight * index / 4);
          context.beginPath(); context.moveTo(left, y); context.lineTo(width - right, y); context.stroke();
          const value = maximum * (1 - index / 4);
          context.fillText(formatRate(value), 2, y + 3);
        }
        if (points.length > 1) {
          context.setLineDash([]);
          const start = Number(points[0].timestamp_unix_seconds);
          const end = Number(points.at(-1).timestamp_unix_seconds);
          [0, .5, 1].forEach(fraction => {
            const timestamp = start + (end - start) * fraction;
            const text = new Date(timestamp * 1000).toLocaleTimeString(state.language === 'zh' ? 'zh-CN' : 'en', { hour: '2-digit', minute: '2-digit' });
            const x = left + plotWidth * fraction;
            const textWidth = context.measureText(text).width;
            context.fillText(text, Math.max(left, Math.min(width - right - textWidth, x - textWidth / 2)), height - 8);
          });
          const drawSeries = (key, color) => {
            context.beginPath();
            context.strokeStyle = color;
            context.lineWidth = cssNumber('--chart-stroke-width', 2);
            const expectedStep = Number(state.historyMeta?.step_seconds || state.historyMeta?.sample_interval_seconds || 5);
            points.forEach((point, index) => {
              const timestamp = Number(point.timestamp_unix_seconds);
              const x = left + plotWidth * (timestamp - start) / Math.max(1, end - start);
              const y = top + plotHeight * (1 - Math.min(maximum, Number(point[key]) || 0) / maximum);
              const previousTimestamp = index ? Number(points[index - 1].timestamp_unix_seconds) : timestamp;
              if (!index || timestamp - previousTimestamp > expectedStep * 2.5) context.moveTo(x, y); else context.lineTo(x, y);
            });
            context.stroke();
          };
          drawSeries('inbound_bps', inboundColor);
          drawSeries('outbound_bps', outboundColor);
        }
        context.fillStyle = inboundColor;
        context.fillRect(left, 8, 12, 3);
        context.fillStyle = label;
        context.fillText(t('inbound'), left + 17, 13);
        const firstWidth = context.measureText(t('inbound')).width;
        const secondX = left + firstWidth + 42;
        context.fillStyle = outboundColor;
        context.fillRect(secondX, 8, 12, 3);
        context.fillStyle = label;
        context.fillText(t('outbound'), secondX + 17, 13);
        const latest = currentTrafficPoint();
        elements.traffic_chart_summary.textContent = points.length > 1 ? `${t('inbound')}: ${formatRate(latest.inbound_bps)}. ${t('outbound')}: ${formatRate(latest.outbound_bps)}.` : t('noTrendData');
      }

      function drawServiceTrendChart() {
        const setup = canvasSetup(elements.service_trend_chart);
        if (!setup) return;
        const { context, width, height } = setup;
        const points = state.serviceTrafficHistory;
        const left = 48, right = 14, top = 25, bottom = 26;
        const plotWidth = Math.max(1, width - left - right);
        const plotHeight = Math.max(1, height - top - bottom);
        const trafficHeight = plotHeight * .63;
        const activityTop = top + trafficHeight + 18;
        const activityHeight = Math.max(18, plotHeight - trafficHeight - 18);
        const grid = cssColor('--chart-grid');
        const label = cssColor('--chart-label');
        const colors = [cssColor('--accent'), cssColor('--primary'), cssColor('--success'), cssColor('--danger')];
        context.font = '10px "Segoe UI", sans-serif';
        context.lineWidth = 1;
        context.strokeStyle = grid;
        context.fillStyle = label;
        context.setLineDash(cssDash('--chart-grid-dash'));
        if (points.length < 2) {
          context.beginPath(); context.moveTo(left, top + trafficHeight); context.lineTo(width - right, top + trafficHeight); context.stroke();
          const message = t('noTrendData');
          context.fillText(message, Math.max(left, left + plotWidth / 2 - context.measureText(message).width / 2), top + trafficHeight / 2);
          return;
        }
        const start = Number(points[0].timestamp_unix_seconds);
        const end = Number(points.at(-1).timestamp_unix_seconds);
        const trafficMaximum = niceMaximum(Math.max(0, ...points.flatMap(point => [Number(point.inbound_bps) || 0, Number(point.outbound_bps) || 0])));
        const activityMaximum = niceMaximum(Math.max(0, ...points.flatMap(point => [Number(point.active_connections || 0) + Number(point.active_sessions || 0), Number(point.errors_per_second) || 0])));
        for (let index = 0; index <= 3; index += 1) {
          const y = top + trafficHeight * index / 3;
          context.beginPath(); context.moveTo(left, y); context.lineTo(width - right, y); context.stroke();
          context.fillText(formatRate(trafficMaximum * (1 - index / 3)), 2, y + 3);
        }
        context.beginPath(); context.moveTo(left, activityTop + activityHeight); context.lineTo(width - right, activityTop + activityHeight); context.stroke();
        context.setLineDash([]);
        const expectedStep = Number(state.serviceHistoryMeta?.step_seconds || state.serviceHistoryMeta?.sample_interval_seconds || 5);
        const drawSeries = (valueForPoint, color, areaTop, areaHeight, maximum, dashed = false) => {
          context.beginPath();
          context.strokeStyle = color;
          context.lineWidth = cssNumber('--chart-stroke-width', 2);
          context.setLineDash(dashed ? [5, 4] : []);
          points.forEach((point, index) => {
            const timestamp = Number(point.timestamp_unix_seconds);
            const x = left + plotWidth * (timestamp - start) / Math.max(1, end - start);
            const value = Math.max(0, Number(valueForPoint(point)) || 0);
            const y = areaTop + areaHeight * (1 - Math.min(maximum, value) / Math.max(1, maximum));
            const previousTimestamp = index ? Number(points[index - 1].timestamp_unix_seconds) : timestamp;
            if (!index || timestamp - previousTimestamp > expectedStep * 2.5) context.moveTo(x, y); else context.lineTo(x, y);
          });
          context.stroke();
          context.setLineDash([]);
        };
        drawSeries(point => point.inbound_bps, colors[0], top, trafficHeight, trafficMaximum);
        drawSeries(point => point.outbound_bps, colors[1], top, trafficHeight, trafficMaximum);
        drawSeries(point => Number(point.active_connections || 0) + Number(point.active_sessions || 0), colors[2], activityTop, activityHeight, activityMaximum);
        drawSeries(point => point.errors_per_second, colors[3], activityTop, activityHeight, activityMaximum, true);
        [0, .5, 1].forEach(fraction => {
          const timestamp = start + (end - start) * fraction;
          const text = new Date(timestamp * 1000).toLocaleString(state.language === 'zh' ? 'zh-CN' : 'en', state.serviceTrendRange === '1h' || state.serviceTrendRange === '12h' ? { hour: '2-digit', minute: '2-digit' } : { month: '2-digit', day: '2-digit' });
          const x = left + plotWidth * fraction;
          context.fillStyle = label;
          context.fillText(text, Math.max(left, Math.min(width - right - context.measureText(text).width, x - context.measureText(text).width / 2)), height - 7);
        });
        const legends = [[t('inbound'), colors[0]], [t('outbound'), colors[1]], [t('workload'), colors[2]], [t('errors'), colors[3]]];
        let legendX = left;
        legends.forEach(([text, color]) => {
          context.fillStyle = color; context.fillRect(legendX, 7, 11, 3);
          context.fillStyle = label; context.fillText(text, legendX + 15, 12);
          legendX += 24 + context.measureText(text).width;
        });
      }

      function drawBarChart(canvas, items, horizontal = false, semanticFailure = false) {
        const setup = canvasSetup(canvas);
        if (!setup) return;
        const { context, width, height } = setup;
        const labelColor = cssColor('--chart-label');
        const gridColor = cssColor('--chart-grid');
        const accent = cssColor('--accent');
        const primary = cssColor('--primary');
        const danger = cssColor('--danger');
        const warning = cssColor('--warning');
        context.font = '10px "Segoe UI", sans-serif';
        context.fillStyle = labelColor;
        if (!items.length) {
          const message = t('noClients');
          context.fillText(message, Math.max(8, width / 2 - context.measureText(message).width / 2), height / 2);
          return;
        }
        if (horizontal) {
          const left = 100, right = 28, top = 12, bottom = 10;
          const rowHeight = (height - top - bottom) / Math.max(1, items.length);
          const maximum = Math.max(1, ...items.map(item => Number(item.value) || 0));
          items.forEach((item, index) => {
            const y = top + index * rowHeight + rowHeight * .2;
            const barHeight = Math.max(7, rowHeight * .42);
            context.fillStyle = labelColor;
            context.fillText(item.label, 2, y + barHeight - 1);
            context.fillStyle = gridColor;
            context.fillRect(left, y, width - left - right, barHeight);
            const barWidth = (width - left - right) * (Number(item.value) || 0) / maximum;
            if (item.color) context.fillStyle = item.color.startsWith('--') ? cssColor(item.color) : item.color;
            else {
              const gradient = context.createLinearGradient(left, 0, width - right, 0);
              gradient.addColorStop(0, semanticFailure ? warning : accent); gradient.addColorStop(1, semanticFailure ? danger : primary);
              context.fillStyle = gradient;
            }
            context.fillRect(left, y, barWidth, barHeight);
            context.fillStyle = labelColor;
            context.fillText(String(item.value), width - right + 5, y + barHeight - 1);
          });
          return;
        }
        const left = 34, right = 10, top = 14, bottom = 34;
        const plotWidth = width - left - right;
        const plotHeight = height - top - bottom;
        const maximum = Math.max(1, ...items.map(item => Number(item.value) || 0));
        const cellWidth = plotWidth / Math.max(1, items.length);
        items.forEach((item, index) => {
          const barWidth = Math.max(10, Math.min(34, cellWidth * .56));
          const x = left + cellWidth * index + (cellWidth - barWidth) / 2;
          const barHeight = plotHeight * (Number(item.value) || 0) / maximum;
          context.fillStyle = gridColor;
          context.fillRect(x, top, barWidth, plotHeight);
          if (item.color) context.fillStyle = item.color.startsWith('--') ? cssColor(item.color) : item.color;
          else {
            const gradient = context.createLinearGradient(0, top + plotHeight, 0, top);
            gradient.addColorStop(0, semanticFailure ? warning : accent); gradient.addColorStop(1, semanticFailure ? danger : primary);
            context.fillStyle = gradient;
          }
          context.fillRect(x, top + plotHeight - barHeight, barWidth, barHeight);
          context.fillStyle = labelColor;
          const shortLabel = item.label.length > 8 ? item.label.slice(0, 7) + '…' : item.label;
          const textWidth = context.measureText(shortLabel).width;
          context.fillText(shortLabel, x + barWidth / 2 - textWidth / 2, height - 12);
          const number = String(item.value);
          context.fillText(number, x + barWidth / 2 - context.measureText(number).width / 2, Math.max(10, top + plotHeight - barHeight - 5));
        });
      }

      function drawGroupedHorizontalChart(canvas, groups) {
        const setup = canvasSetup(canvas);
        if (!setup) return;
        const { context, width, height } = setup;
        const rows = groups.flatMap(group => group.items);
        const labelColor = cssColor('--chart-label');
        const gridColor = cssColor('--chart-grid');
        const colors = [cssColor('--accent'), cssColor('--primary')];
        context.font = '9px "Segoe UI", sans-serif';
        if (!rows.length) {
          const message = t('noClients');
          context.fillStyle = labelColor;
          context.fillText(message, Math.max(8, width / 2 - context.measureText(message).width / 2), height / 2);
          return;
        }
        const left = 112, right = 28, top = 8, headingHeight = 17;
        const rowHeight = Math.max(17, (height - top - groups.length * headingHeight - 5) / Math.max(1, rows.length));
        const maximum = Math.max(1, ...rows.map(item => Number(item.value) || 0));
        let y = top;
        groups.forEach((group, groupIndex) => {
          context.fillStyle = colors[groupIndex % colors.length];
          context.font = '700 9px "Segoe UI", sans-serif';
          context.fillText(group.label, 2, y + 9);
          y += headingHeight;
          context.font = '9px "Segoe UI", sans-serif';
          group.items.forEach(item => {
            const barHeight = Math.max(7, rowHeight * .42);
            context.fillStyle = labelColor;
            context.fillText(item.label, 10, y + barHeight - 1);
            context.fillStyle = gridColor;
            context.fillRect(left, y, Math.max(1, width - left - right), barHeight);
            context.fillStyle = colors[groupIndex % colors.length];
            context.fillRect(left, y, Math.max(0, width - left - right) * (Number(item.value) || 0) / maximum, barHeight);
            context.fillStyle = labelColor;
            context.fillText(String(item.value), width - right + 6, y + barHeight - 1);
            y += rowHeight;
          });
        });
      }

      function barRows(items) {
        const container = document.createElement('div');
        container.className = 'bar-list';
        const maximum = Math.max(1, ...items.map(item => Number(item.value) || 0));
        items.forEach(item => {
          const row = document.createElement('div');
          row.className = 'bar-row';
          const label = document.createElement('span');
          const track = document.createElement('div');
          const fill = document.createElement('div');
          const value = document.createElement('strong');
          label.textContent = item.label;
          track.className = 'bar-track';
          fill.className = 'bar-fill';
          fill.style.width = `${(Number(item.value) || 0) / maximum * 100}%`;
          value.textContent = item.display ?? String(item.value);
          track.append(fill);
          row.append(label, track, value);
          container.append(row);
        });
        return container;
      }

      function renderMetricPanel(container, title, hero, heroLabel, rows) {
        container.replaceChildren();
        const heading = document.createElement('div');
        heading.className = 'panel-heading';
        const h3 = document.createElement('h3');
        h3.textContent = title;
        heading.append(h3);
        const metricHero = document.createElement('div');
        metricHero.className = 'metric-hero';
        const strong = document.createElement('strong');
        const span = document.createElement('span');
        strong.textContent = hero;
        span.textContent = heroLabel;
        metricHero.append(strong, span);
        container.append(heading, metricHero, barRows(rows));
      }

      function donutCard(title, numerator, denominator, detail) {
        const card = document.createElement('div');
        card.className = 'donut-card';
        const ratio = denominator > 0 ? Math.max(0, Math.min(1, numerator / denominator)) : 0;
        const circumference = 100;
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 42 42');
        svg.setAttribute('aria-hidden', 'true');
        const track = document.createElementNS(svg.namespaceURI, 'circle');
        const value = document.createElementNS(svg.namespaceURI, 'circle');
        [track, value].forEach(circle => { circle.setAttribute('cx', '21'); circle.setAttribute('cy', '21'); circle.setAttribute('r', '15.9155'); });
        track.setAttribute('class', 'donut-track');
        value.setAttribute('class', 'donut-value');
        value.setAttribute('stroke-dasharray', `${ratio * circumference} ${circumference}`);
        svg.append(track, value);
        const copy = document.createElement('div');
        copy.className = 'donut-copy';
        const strong = document.createElement('strong');
        const span = document.createElement('span');
        const small = document.createElement('small');
        strong.textContent = denominator > 0 ? `${Math.round(ratio * 100)}%` : '—';
        span.textContent = title;
        small.textContent = detail;
        copy.append(strong, span, small);
        card.append(svg, copy);
        return card;
      }

      function renderMetrics() {
        const dashboard = state.dashboard;
        const metrics = dashboard.metrics;
        const activeTotal = metrics.tcp_active_connections + metrics.udp_active_sessions + metrics.http_active_connections + metrics.https_active_connections + metrics.sni_active_connections + metrics.socks5_active_connections + metrics.socks5_udp_active_associations + metrics.http_proxy_active_connections;
        const requestTotal = metrics.socks5_requests_total + metrics.http_proxy_requests_total + metrics.http_requests_total + metrics.https_requests_total;
        const socks5FailureTotal = sumMetrics([
          'socks5_authentication_failures', 'socks5_connect_failures', 'socks5_handshake_errors',
          'socks5_bind_failures_total', 'socks5_bind_accept_timeouts_total', 'socks5_bind_peer_rejections_total',
          'socks5_udp_fragment_rejections_total', 'socks5_udp_fragment_timeouts_total', 'socks5_udp_fragment_source_rejections_total'
        ]);
        const failureTotal = metrics.tcp_failed_connections + metrics.udp_dropped_packets + metrics.http_failed_requests + metrics.https_handshake_failures_total + socks5FailureTotal + metrics.http_proxy_authentication_failures;
        const traffic = aggregateTraffic();
        elements.metrics_kpis.replaceChildren(
          createKpi(formatDuration(metrics.uptime_seconds), t('serverUptime')),
          createKpi(String(activeTotal), t('activeSessions')),
          createKpi(String(requestTotal), t('requestsTotal')),
          createKpi(String(failureTotal), t('failuresTotal')),
          createKpi(`${formatBytes(traffic.inbound)} / ${formatBytes(traffic.outbound)}`, t('totalTraffic'))
        );

        drawBarChart(elements.activity_chart, [
          { label: 'TCP', value: metrics.tcp_active_connections },
          { label: 'UDP', value: metrics.udp_active_sessions },
          { label: 'HTTP', value: metrics.http_active_connections + metrics.https_active_connections },
          { label: 'SNI', value: metrics.sni_active_connections },
          { label: 'SOCKS5', value: metrics.socks5_active_connections + metrics.socks5_udp_active_associations },
          { label: 'Proxy', value: metrics.http_proxy_active_connections }
        ], true);
        drawBarChart(elements.failure_chart, [
          { label: 'TCP', value: metrics.tcp_failed_connections + metrics.tcp_rejected_policy_limit + metrics.tcp_rejected_global_limit + metrics.tcp_rejected_pending_limit },
          { label: 'UDP', value: metrics.udp_dropped_packets + metrics.udp_transport_errors },
          { label: 'Web', value: metrics.http_failed_requests + metrics.https_handshake_failures_total + metrics.sni_client_hello_errors + metrics.sni_unknown_hostname },
          { label: 'SOCKS5', value: socks5FailureTotal },
          { label: 'Proxy', value: metrics.http_proxy_authentication_failures + metrics.http_proxy_malformed_requests + metrics.http_proxy_connect_failures }
        ], true, true);

        renderMetricPanel(elements.tcp_metric_panel, t('tcpMetrics'), String(metrics.tcp_active_connections), t('active'), [
          { label: t('pending'), value: metrics.tcp_pending_connections },
          { label: t('rejected'), value: metrics.tcp_rejected_policy_limit + metrics.tcp_rejected_global_limit + metrics.tcp_rejected_pending_limit },
          { label: t('failed'), value: metrics.tcp_failed_connections },
          { label: t('timeouts'), value: metrics.tcp_pairing_timeouts + metrics.tcp_lifetime_timeouts },
          { label: t('traffic'), value: metrics.tcp_bytes_from_public + metrics.tcp_bytes_to_public, display: `${formatBytes(metrics.tcp_bytes_from_public)} / ${formatBytes(metrics.tcp_bytes_to_public)}` }
        ]);

        const udpDropRows = [
          { label: t('drops'), value: dashboard.metrics.udp_dropped_packets },
          { label: 'Oversized', value: dashboard.metrics.udp_dropped_oversized },
          { label: 'Malformed', value: dashboard.metrics.udp_dropped_malformed },
          { label: 'Unknown', value: dashboard.metrics.udp_dropped_unknown_session },
          { label: 'Queue', value: dashboard.metrics.udp_dropped_queue_full },
          { label: 'Policy', value: dashboard.metrics.udp_dropped_policy_session_limit },
          { label: 'Global', value: dashboard.metrics.udp_dropped_global_session_limit },
          { label: 'Bandwidth', value: dashboard.metrics.udp_dropped_bandwidth_limit },
          { label: t('timeouts'), value: dashboard.metrics.udp_attach_timeouts + dashboard.metrics.udp_session_timeouts + dashboard.metrics.udp_reassembly_timeouts }
        ];
        renderMetricPanel(elements.udp_metric_panel, t('udpMetrics'), String(metrics.udp_active_sessions), t('sessions'), udpDropRows);

        renderMetricPanel(elements.proxy_metric_panel, t('proxyMetrics'), String(metrics.socks5_active_connections + metrics.http_proxy_active_connections), t('active'), [
          { label: 'SOCKS5 requests', value: metrics.socks5_requests_total },
          { label: 'SOCKS5 auth', value: metrics.socks5_authentication_failures },
          { label: 'SOCKS5 UDP', value: metrics.socks5_udp_active_associations },
          { label: `BIND ${t('active')} / ${t('requestsTotal')}`, value: metrics.socks5_bind_active_leases, display: `${metrics.socks5_bind_active_leases} / ${metrics.socks5_bind_requests_total}` },
          { label: `UDP FRAG ${t('completed')} / ${t('failed')}`, value: metrics.socks5_udp_fragmented_datagrams_completed_total, display: `${metrics.socks5_udp_fragmented_datagrams_completed_total} / ${metrics.socks5_udp_fragment_rejections_total + metrics.socks5_udp_fragment_timeouts_total + metrics.socks5_udp_fragment_source_rejections_total}` },
          { label: 'HTTP requests', value: metrics.http_proxy_requests_total },
          { label: 'HTTP failures', value: metrics.http_proxy_authentication_failures + metrics.http_proxy_malformed_requests + metrics.http_proxy_connect_failures },
          { label: t('traffic'), value: metrics.socks5_bytes_from_public + metrics.socks5_bytes_to_public + metrics.socks5_udp_bytes_from_public + metrics.socks5_udp_bytes_to_public + metrics.http_proxy_bytes_from_public + metrics.http_proxy_bytes_to_public, display: `${formatBytes(metrics.socks5_bytes_from_public + metrics.socks5_udp_bytes_from_public + metrics.http_proxy_bytes_from_public)} / ${formatBytes(metrics.socks5_bytes_to_public + metrics.socks5_udp_bytes_to_public + metrics.http_proxy_bytes_to_public)}` }
        ]);

        renderMetricPanel(elements.web_metric_panel, t('webMetrics'), String(metrics.http_active_connections + metrics.https_active_connections + metrics.sni_active_connections), t('active'), [
          { label: 'HTTP requests', value: metrics.http_requests_total },
          { label: 'HTTP failed', value: metrics.http_failed_requests },
          { label: 'H2 streams / requests', value: metrics.http2_active_streams, display: `${metrics.http2_active_streams} / ${metrics.http2_requests_total}` },
          { label: 'gRPC requests / failed', value: metrics.grpc_requests_total, display: `${metrics.grpc_requests_total} / ${metrics.grpc_failures_total}` },
          { label: 'H2 reuse / connections', value: metrics.http2_backend_reused_total, display: `${metrics.http2_backend_reused_total} / ${metrics.http2_backend_connections_total}` },
          { label: 'GOAWAY / reconnect', value: metrics.http2_backend_goaway_total, display: `${metrics.http2_backend_goaway_total} / ${metrics.http2_backend_reconnects_total}` },
          { label: 'HTTPS requests', value: metrics.https_requests_total },
          { label: 'TLS handshake', value: metrics.https_handshake_failures_total + metrics.tls_handshake_failures_total },
          { label: 'SNI connections', value: metrics.sni_connections_total },
          { label: 'Unknown SNI', value: metrics.sni_unknown_hostname },
          { label: t('traffic'), value: metrics.http_bytes_from_public + metrics.http_bytes_to_public + metrics.sni_bytes_from_public + metrics.sni_bytes_to_public, display: `${formatBytes(metrics.http_bytes_from_public + metrics.sni_bytes_from_public)} / ${formatBytes(metrics.http_bytes_to_public + metrics.sni_bytes_to_public)}` }
        ]);

        elements.network_health_panel.replaceChildren();
        const networkHeading = document.createElement('div');
        networkHeading.className = 'panel-heading';
        const networkTitle = document.createElement('h3');
        networkTitle.textContent = `${t('p2pMetrics')} · ${t('certificateMetrics')}`;
        networkHeading.append(networkTitle);
        const donutGrid = document.createElement('div');
        donutGrid.className = 'donut-grid';
        const p2pTotal = metrics.p2p_direct_connections_total + metrics.p2p_relay_fallbacks_total;
        donutGrid.append(
          donutCard(t('direct'), metrics.p2p_direct_connections_total, p2pTotal, `${metrics.p2p_session_offers_total} offers · ${metrics.p2p_relay_fallbacks_total} ${t('relay').toLowerCase()}`),
          donutCard(t('valid'), metrics.certificates_active, metrics.certificates_managed, `${metrics.certificates_expiring_30d} ${t('expiring').toLowerCase()} · ${metrics.certificates_expired} ${t('expired').toLowerCase()}`)
        );
        elements.network_health_panel.append(networkHeading, donutGrid);

        renderMetricPanel(elements.system_metric_panel, t('systemMetrics'), formatDuration(metrics.uptime_seconds), t('serverUptime'), [
          { label: t('reconnects'), value: metrics.tunnel_reconnects_total },
          { label: t('authenticationFailures'), value: metrics.authentication_failures_total },
          { label: 'Control errors', value: metrics.control_protocol_errors_total },
          { label: t('orders'), value: metrics.acme_orders_total, display: `${metrics.acme_orders_total} / ${metrics.acme_orders_failed_total}` },
          { label: t('renewals'), value: metrics.acme_renewals_total, display: `${metrics.acme_renewals_total} / ${metrics.acme_renewal_failures_total}` },
          { label: t('challenges'), value: metrics.acme_http01_challenges_total }
        ]);
      }

      function policyTitle(type, policy) {
        if (type === 'tcp') return `${policy.name} · TCP :${policy.public_port}`;
        if (type === 'udp') return `${policy.name} · UDP :${policy.public_port}`;
        if (type === 'ports') return `${policy.name} · ${String(policy.protocol).toUpperCase()} ${policy.public_ports}`;
        if (type === 'http') return `${policy.name} · ${policy.hostname}`;
        if (type === 'sni') return `${policy.name} · ${policy.hostname}`;
        if (type === 'secret') return policy.name;
        if (type === 'socks5') return `${policy.name} · SOCKS5 :${policy.public_port}`;
        return `${policy.name} · HTTP :${policy.public_port}`;
      }

      function policyEndpoint(type, policy) {
        if (type === 'ports') return `${clientName(policy.client_id)} · :${policy.public_ports} → ${policy.target_host}:${policy.target_ports}`;
        if (type === 'http') return `${policy.tls?.mode === 'acme' ? 'https' : 'http'}://${policy.hostname} → ${clientName(policy.client_id)} · ${policy.target_addr}`;
        if (type === 'secret') return `${clientName(policy.provider_client_id)} → ${policy.target_addr}`;
        if (['tcp', 'udp', 'sni'].includes(type)) return `${clientName(policy.client_id)} → ${policy.target_addr}`;
        return `${clientName(policy.client_id)} · ${policy.username}@:${policy.public_port}`;
      }

      function policyStats(type, policy) {
        if (type === 'tcp') return [
          [t('active'), `${policy.active_connections}/${policy.max_connections}`], [t('rejected'), policy.rejected_connections], [t('failed'), policy.failed_connections], [t('traffic'), `${formatBytes(policy.bytes_from_public)} / ${formatBytes(policy.bytes_to_public)}`]
        ];
        if (type === 'udp') {
          const dropBreakdown = `${policy.dropped_oversized}/${policy.dropped_malformed}/${policy.dropped_unknown_session}/${policy.dropped_queue_full}`;
          const timeoutBreakdown = policy.attach_timeouts;
          return [[t('sessions'), `${policy.active_sessions}/${policy.max_sessions}`], [t('packets'), `${policy.packets_from_public}/${policy.packets_to_public}`], [t('drops'), `${policy.dropped_packets} (${dropBreakdown})`], [t('timeouts'), timeoutBreakdown], [t('traffic'), `${formatBytes(policy.bytes_from_public)} / ${formatBytes(policy.bytes_to_public)}`]];
        }
        if (type === 'ports') return [[t('connections'), policy.protocol === 'tcp' ? policy.active_connections : policy.active_sessions], ['Mappings', `${policy.online_mappings}/${policy.mapping_count}`], [t('traffic'), `${formatBytes(policy.bytes_from_public)} / ${formatBytes(policy.bytes_to_public)}`]];
        if (type === 'http') return [[t('active'), `${policy.active_connections}/${policy.max_connections}`], ['H2', `${policy.http2_active_streams || 0}/${policy.http2_requests_total || 0}`], ['gRPC', policy.grpc_requests_total || 0], ['Reuse', `${policy.http2_backend_reused_total || 0}/${policy.http2_backend_connections_total || 0}`], [t('failed'), Number(policy.failed_requests || 0) + Number(policy.grpc_failures_total || 0)], [t('certificate'), tlsStatusText(policy.tls?.status)]];
        if (type === 'sni') return [[t('active'), policy.active_connections], [t('connections'), policy.connections_total], ['Unknown SNI', policy.unknown_sni], [t('traffic'), `${formatBytes(policy.bytes_from_public)} / ${formatBytes(policy.bytes_to_public)}`]];
        if (type === 'secret') return [[t('active'), `${policy.active_connections}/${policy.max_connections}`], [t('connections'), policy.connections_total], [t('rejected'), policy.rejected_connections], [t('traffic'), `${formatBytes(policy.bytes_from_visitor)} / ${formatBytes(policy.bytes_to_visitor)}`]];
        if (type === 'socks5') return [
          [t('active'), policy.active_connections],
          [t('requestsTotal'), policy.requests_total],
          [`BIND ${t('active')}/${t('requestsTotal')}`, `${policy.bind_active_leases || 0}/${policy.bind_requests_total || 0}`],
          ['UDP', policy.udp_active_associations],
          [`UDP FRAG ${t('completed')}/${t('failed')}`, `${policy.udp_fragmented_datagrams_completed_total || 0}/${socks5FragmentFailureTotal(policy)}`],
          [t('failed'), policyErrorTotal(type, policy)],
          [t('traffic'), `${formatBytes(Number(policy.bytes_from_public || 0) + Number(policy.udp_bytes_from_public || 0))} / ${formatBytes(Number(policy.bytes_to_public || 0) + Number(policy.udp_bytes_to_public || 0))}`]
        ];
        return [[t('active'), policy.active_connections], [t('requestsTotal'), policy.requests_total], ['CONNECT', policy.connect_requests], [t('failed'), policy.authentication_failures + policy.malformed_requests + policy.connect_failures]];
      }

      function socks5CapabilityText(policy) {
        const capabilities = policy.capabilities || {};
        if (capabilities.connect === true && capabilities.bind === true && capabilities.udp_associate === true && capabilities.udp_fragmentation === true) {
          return t('socks5CapabilitiesWithUdp');
        }
        if (capabilities.connect === true && capabilities.bind === true && capabilities.udp_associate === false && capabilities.udp_fragmentation === false) {
          return t('socks5CapabilitiesTcpOnly');
        }
        const entries = [
          ['CONNECT', 'connect'], ['BIND', 'bind'], ['UDP ASSOCIATE', 'udp_associate'], ['UDP FRAG', 'udp_fragmentation']
        ];
        const available = entries.filter(([, key]) => capabilities[key] === true).map(([label]) => label);
        const unavailable = entries.filter(([, key]) => capabilities[key] !== true).map(([label]) => label);
        return t('socks5CapabilitiesPartial', {
          available: available.length ? available.join(', ') : '—',
          unavailable: unavailable.length ? unavailable.join(', ') : '—'
        });
      }

      function socks5FragmentFailureTotal(policy) {
        return Number(policy.udp_fragment_rejections_total || 0) + Number(policy.udp_fragment_timeouts_total || 0) + Number(policy.udp_fragment_source_rejections_total || 0);
      }

      function policyWorkload(type, policy) {
        if (type === 'udp') return Number(policy.active_sessions || 0);
        if (type === 'ports') return Number(policy.active_connections || 0) + Number(policy.active_sessions || 0);
        if (type === 'socks5') return Number(policy.active_connections || 0) + Number(policy.udp_active_associations || 0);
        return Number(policy.active_connections || 0);
      }

      function policyErrorTotal(type, policy) {
        if (type === 'tcp') return Number(policy.rejected_connections || 0) + Number(policy.failed_connections || 0);
        if (type === 'udp') return Number(policy.dropped_packets || 0) + Number(policy.attach_timeouts || 0);
        if (type === 'ports') return Number(policy.failed_connections || 0) + Number(policy.dropped_packets || 0);
        if (type === 'http') return Number(policy.failed_requests || 0);
        if (type === 'sni') return Number(policy.unknown_sni || 0);
        if (type === 'secret') return Number(policy.rejected_connections || 0) + Number(policy.failed_connections || 0);
        if (type === 'socks5') return Number(policy.authentication_failures || 0) + Number(policy.connect_failures || 0) + Number(policy.handshake_errors || 0) + Number(policy.bind_failures_total || 0) + Number(policy.bind_accept_timeouts_total || 0) + Number(policy.bind_peer_rejections_total || 0) + socks5FragmentFailureTotal(policy);
        return Number(policy.authentication_failures || 0) + Number(policy.connect_failures || 0) + Number(policy.malformed_requests || 0);
      }

      function policyTrafficBytes(type, policy) {
        if (type === 'secret') return Number(policy.bytes_from_visitor || 0) + Number(policy.bytes_to_visitor || 0);
        if (type === 'socks5') return Number(policy.bytes_from_public || 0) + Number(policy.bytes_to_public || 0) + Number(policy.udp_bytes_from_public || 0) + Number(policy.udp_bytes_to_public || 0);
        return Number(policy.bytes_from_public || 0) + Number(policy.bytes_to_public || 0);
      }

      function drawServiceStatusChart() {
        const policies = state.visibleServicePolicies || [];
        const enabled = policies.filter(policy => policy.enabled).length;
        const online = policies.filter(isPolicyOnline).length;
        drawBarChart(elements.service_status_chart, [
          { label: t('online'), value: online, color: '--success' },
          { label: t('offline'), value: Math.max(0, enabled - online), color: '--warning' },
          { label: t('disabled'), value: Math.max(0, policies.length - enabled), color: '--faint' },
          { label: t('workload'), value: policies.reduce((total, policy) => total + policyWorkload(state.route.service, policy), 0), color: '--primary' }
        ], true);
      }

      function renderServiceInsights(type, visiblePolicies) {
        state.visibleServicePolicies = visiblePolicies;
        const protocol = serviceHistoryProtocol(type);
        if (state.serviceHistoryProtocol !== protocol) {
          state.serviceHistoryProtocol = protocol;
          const cached = state.historyCache.get(historyCacheKey(state.serviceTrendRange, protocol));
          state.serviceTrafficHistory = cached && Date.now() - cached.fetchedAt < 45000 && Array.isArray(cached.payload.points) ? cached.payload.points : [];
          state.serviceHistoryMeta = cached?.payload || null;
        }
        elements.service_insights.classList.remove('hidden');
        elements.service_trend_title.textContent = `${t(POLICY_TYPES[type].titleKey)} · ${t('protocolTrend')}`;
        const online = visiblePolicies.filter(isPolicyOnline).length;
        const workload = visiblePolicies.reduce((total, policy) => total + policyWorkload(type, policy), 0);
        const errors = visiblePolicies.reduce((total, policy) => total + policyErrorTotal(type, policy), 0);
        const traffic = visiblePolicies.reduce((total, policy) => total + policyTrafficBytes(type, policy), 0);
        elements.service_insight_kpis.replaceChildren(
          createInsightKpi(String(visiblePolicies.length), t('forwardingServices')),
          createInsightKpi(String(online), t('online')),
          createInsightKpi(String(workload), t('workload')),
          createInsightKpi(String(errors), t('errors')),
          createInsightKpi(formatBytes(traffic), t('totalTraffic'))
        );
        document.querySelectorAll('[data-service-range]').forEach(button => button.classList.toggle('active', button.dataset.serviceRange === state.serviceTrendRange));
        drawServiceTrendChart();
        drawServiceStatusChart();
      }

      function tlsStatusText(status) {
        const map = { disabled: 'certificateDisabled', pending: 'certificatePending', issuing: 'certificateIssuing', active: 'certificateActive', renewing: 'certificateRenewing', error: 'certificateError', expired: 'certificateExpired' };
        return t(map[status] || 'unknown');
      }

      function policySearchText(type, policy) {
        return [policy.name, policy.client_id, policy.provider_client_id, policy.allowed_client_id, policy.hostname, policy.target_addr, policy.target_host, policy.public_port, policy.public_ports, policy.username, clientName(policy.client_id), clientName(policy.provider_client_id)].filter(Boolean).join(' ').toLowerCase();
      }

      function matchesPolicyFilter(type, policy) {
        const query = state.serviceSearch.trim().toLowerCase();
        if (query && !policySearchText(type, policy).includes(query)) return false;
        if (state.serviceStatus === 'online' && !isPolicyOnline(policy)) return false;
        if (state.serviceStatus === 'offline' && isPolicyOnline(policy)) return false;
        if (state.serviceStatus === 'enabled' && !policy.enabled) return false;
        if (state.serviceStatus === 'disabled' && policy.enabled) return false;
        return true;
      }

      function actionButton(label, handler, className = 'soft-button', action = '') {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = className;
        button.textContent = label;
        if (action) button.dataset.action = action;
        button.addEventListener('click', handler);
        return button;
      }

      function createServiceCard(type, policy) {
        const card = document.createElement('article');
        card.className = 'service-card';
        card.dataset.policyId = policy.id;
        const content = document.createElement('div');
        const heading = document.createElement('h3');
        if (state.identity.role !== 'auditor') {
          const selector = document.createElement('label'); selector.className = 'policy-select';
          const checkbox = document.createElement('input'); checkbox.type = 'checkbox';
          const selectionKey = `${type}:${policy.id}`;
          checkbox.checked = state.selectedPolicies.has(selectionKey);
          checkbox.addEventListener('change', () => {
            if (checkbox.checked) state.selectedPolicies.add(selectionKey); else state.selectedPolicies.delete(selectionKey);
            updateBulkToolbar();
          });
          selector.append(checkbox); heading.append(selector);
        }
        const title = document.createElement('span');
        title.textContent = policyTitle(type, policy);
        const enabledBadge = document.createElement('span');
        enabledBadge.className = 'badge';
        enabledBadge.textContent = policy.enabled ? t('enabled') : t('disabled');
        const onlineBadge = document.createElement('span');
        onlineBadge.className = `badge ${isPolicyOnline(policy) ? 'online' : 'offline'}`;
        onlineBadge.textContent = isPolicyOnline(policy) ? t('online') : t('offline');
        heading.append(title, enabledBadge, onlineBadge);
        const endpoint = document.createElement('div');
        endpoint.className = 'endpoint';
        endpoint.textContent = policyEndpoint(type, policy);
        const stats = document.createElement('div');
        stats.className = 'service-stats';
        policyStats(type, policy).forEach(([label, value]) => {
          const span = document.createElement('span');
          const strong = document.createElement('strong');
          strong.textContent = `${label}: `;
          span.append(strong, document.createTextNode(String(value ?? 0)));
          stats.append(span);
        });
        content.append(heading, endpoint, stats);
        if (type === 'socks5') {
          const capability = document.createElement('div');
          capability.className = 'capability-note';
          capability.textContent = socks5CapabilityText(policy);
          content.append(capability);
        }
        if (type === 'http') {
          const capability = document.createElement('div');
          capability.className = 'capability-note';
          capability.textContent = t('httpTransportCapabilities');
          content.append(capability);
        }
        const errorText = type === 'http' ? policy.tls?.last_error_message : '';
        if (errorText) {
          const error = document.createElement('div');
          error.className = 'service-error';
          error.textContent = errorText;
          content.append(error);
        }
        const actions = document.createElement('div');
        actions.className = 'service-actions';
        if (state.identity.role !== 'auditor') {
          actions.append(
            actionButton(t('editPolicy'), () => beginPolicyEdit(type, policy), 'soft-button', 'edit-policy'),
            actionButton(policy.enabled ? t('disable') : t('enable'), () => setPolicyEnabled(type, policy), 'soft-button', 'toggle-policy')
          );
          const menu = document.createElement('details');
          menu.className = 'action-menu';
          const summary = document.createElement('summary');
          summary.textContent = '•••';
          summary.title = t('moreActions');
          summary.setAttribute('aria-label', t('moreActions'));
          const popover = document.createElement('div');
          popover.className = 'action-menu-popover';
          popover.append(actionButton(t('duplicate'), () => duplicatePolicy(type, policy), 'soft-button', 'duplicate-policy'));
          if (state.identity.role === 'administrator' && ['tcp', 'udp', 'ports', 'http', 'sni', 'socks5', 'http-proxy'].includes(type)) {
            popover.append(actionButton(t('trafficControl'), () => openTrafficControl(type, policy), 'soft-button'));
          }
          if (type === 'http') appendHttpCertificateActions(popover, policy);
          popover.append(actionButton(t('delete'), () => deletePolicy(type, policy), 'danger-button', 'delete-policy'));
          popover.addEventListener('click', event => { if (event.target.closest('button')) menu.removeAttribute('open'); });
          menu.append(summary, popover);
          actions.append(menu);
        }
        card.append(content, actions);
        return card;
      }

      function appendHttpCertificateActions(actions, route) {
        const tls = route.tls || { mode: 'disabled', status: 'disabled', redirect_http_to_https: false };
        const busy = tls.status === 'issuing' || tls.status === 'renewing';
        if (tls.mode === 'disabled') actions.append(actionButton(t('enableAutomaticHttps'), () => updateRouteTls(route.id, 'acme', false)));
        else {
          const disable = actionButton(t('disableHttps'), () => updateRouteTls(route.id, 'disabled', false)); disable.disabled = busy; actions.append(disable);
          const redirect = actionButton(t(tls.redirect_http_to_https ? 'disableRedirect' : 'enableRedirect'), () => updateRouteTls(route.id, 'acme', !tls.redirect_http_to_https)); redirect.disabled = busy; actions.append(redirect);
          const certificate = actionButton(t(tls.status === 'active' ? 'renewCertificate' : 'issueCertificate'), () => runCertificateAction(route.id, tls.status === 'active' ? 'renew' : 'issue')); certificate.disabled = busy; actions.append(certificate);
        }
      }

      function renderServices() {
        const type = state.route.service;
        const isAcme = type === 'acme';
        elements.workspace_service_actions.classList.toggle('hidden', isAcme);
        elements.new_policy.classList.toggle('hidden', isAcme || state.identity.role === 'auditor');
        elements.export_policies.classList.toggle('hidden', isAcme);
        elements.import_policies.classList.toggle('hidden', isAcme || state.identity.role === 'auditor');
        elements.service_toolbar.classList.toggle('hidden', isAcme);
        elements.service_bulk_toolbar.classList.toggle('hidden', isAcme || state.identity.role === 'auditor');
        elements.service_list.classList.toggle('hidden', isAcme);
        elements.service_insights.classList.toggle('hidden', isAcme);
        elements.acme_page.classList.toggle('hidden', !isAcme);
        if (isAcme) return renderAcme();
        const schema = POLICY_TYPES[type];
        if (state.drawer.open) return;
        const policies = state.dashboard[schema.dataKey] || [];
        const visible = policies.filter(policy => matchesPolicyFilter(type, policy));
        renderServiceInsights(type, visible);
        elements.service_count.textContent = t('policyCount', { visible: visible.length, total: policies.length });
        elements.service_list.replaceChildren();
        if (!visible.length) {
          const empty = document.createElement('div');
          empty.className = 'empty-state';
          empty.textContent = t('noPolicies');
          elements.service_list.append(empty);
        } else visible.forEach(policy => elements.service_list.append(createServiceCard(type, policy)));
        populateBulkClientTargets();
        updateBulkToolbar();
      }

      function currentServicePolicies() {
        const schema = POLICY_TYPES[state.route.service];
        return schema ? (state.dashboard[schema.dataKey] || []) : [];
      }

      function selectedServicePolicies() {
        const type = state.route.service;
        return currentServicePolicies().filter(policy => state.selectedPolicies.has(`${type}:${policy.id}`));
      }

      function updateBulkToolbar() {
        if (!POLICY_TYPES[state.route.service]) return;
        const count = selectedServicePolicies().length;
        elements.selected_policy_count.textContent = t('selectedPolicies', { count });
        [elements.bulk_enable_policies, elements.bulk_disable_policies, elements.bulk_migrate_policies, elements.bulk_delete_policies].forEach(button => { button.disabled = count === 0; });
      }

      function populateBulkClientTargets() {
        const current = elements.bulk_client_target.value;
        elements.bulk_client_target.replaceChildren();
        const placeholder = document.createElement('option'); placeholder.value = ''; placeholder.textContent = t('selectClient'); elements.bulk_client_target.append(placeholder);
        (state.dashboard.clients || []).filter(client => client.enabled !== false).forEach(client => {
          const option = document.createElement('option'); option.value = client.client_id; option.textContent = `${client.name} · ${client.platform}`; elements.bulk_client_target.append(option);
        });
        if ([...elements.bulk_client_target.options].some(option => option.value === current)) elements.bulk_client_target.value = current;
      }

      function selectVisiblePolicies() {
        const type = state.route.service;
        currentServicePolicies().filter(policy => matchesPolicyFilter(type, policy)).forEach(policy => state.selectedPolicies.add(`${type}:${policy.id}`));
        renderServices();
      }

      async function bulkSetPoliciesEnabled(enabled) {
        const type = state.route.service;
        const schema = POLICY_TYPES[type];
        const policies = selectedServicePolicies();
        for (const policy of policies) {
          const response = await apiFetch(`/api/v1/${schema.resource}/${policy.id}/enabled`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
          if (!response.ok) return showToast(await responseError(response, 'requestFailed'), true);
        }
        policies.forEach(policy => state.selectedPolicies.delete(`${type}:${policy.id}`));
        showToast(t('bulkCompleted'));
        await loadManagementData({ forceHistory: false });
      }

      async function bulkMigratePolicies() {
        const target = elements.bulk_client_target.value;
        if (!target) return showToast(t('selectClient'), true);
        const type = state.route.service;
        const schema = POLICY_TYPES[type];
        const policies = selectedServicePolicies();
        for (const policy of policies) {
          const values = policyInitialValues(type, policy);
          if (type === 'secret') values.provider_client_id = target; else values.client_id = target;
          const response = await apiFetch(`/api/v1/${schema.resource}/${policy.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(normalizePolicyPayload(type, values)) });
          if (!response.ok) return showToast(await responseError(response, 'requestFailed'), true);
        }
        policies.forEach(policy => state.selectedPolicies.delete(`${type}:${policy.id}`));
        showToast(t('bulkCompleted'));
        await loadManagementData({ forceHistory: false });
      }

      async function bulkDeletePolicies() {
        const type = state.route.service;
        const schema = POLICY_TYPES[type];
        const policies = selectedServicePolicies();
        if (!policies.length || !confirm(t('confirmBulkDelete', { count: policies.length }))) return;
        for (const policy of policies) {
          const response = await apiFetch(`/api/v1/${schema.resource}/${policy.id}`, { method: 'DELETE' });
          if (!response.ok) return showToast(await responseError(response, 'requestFailed'), true);
        }
        policies.forEach(policy => state.selectedPolicies.delete(`${type}:${policy.id}`));
        showToast(t('bulkCompleted'));
        await loadManagementData({ forceHistory: false });
      }

      function downloadJson(filename, value) {
        const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a'); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }

      function exportPolicies() {
        const type = state.route.service;
        if (!POLICY_TYPES[type]) return;
        const policies = currentServicePolicies().map(policy => policyInitialValues(type, policy));
        downloadJson(`linklake-${type}-policies.json`, { format: 'linklake-policy-bundle', version: 1, type, exported_at: new Date().toISOString(), policies });
      }

      async function importPoliciesFile(event) {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) return;
        let bundle;
        try { bundle = JSON.parse(await file.text()); } catch (_) { return showToast(t('invalidImport'), true); }
        const type = state.route.service;
        const schema = POLICY_TYPES[type];
        if (!schema || bundle?.format !== 'linklake-policy-bundle' || bundle.type !== type || !Array.isArray(bundle.policies)) return showToast(t('invalidImport'), true);
        const credentials = [];
        let imported = 0;
        for (const values of bundle.policies.slice(0, 500)) {
          const response = await apiFetch(`/api/v1/${schema.resource}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(normalizePolicyPayload(type, values)) });
          if (!response.ok) return showToast(await responseError(response, 'requestFailed'), true, 0);
          const result = await response.json().catch(() => ({}));
          const policy = result.policy || result;
          if (result.access_key || result.password) credentials.push({ type, id: policy.id, name: policy.name, username: policy.username || null, access_key: result.access_key || null, password: result.password || null });
          if (type === 'http' && policy.id && values.tls_mode) {
            const tlsResponse = await apiFetch(`/api/v1/http-routes/${policy.id}/tls`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: values.tls_mode, redirect_http_to_https: Boolean(values.redirect_http_to_https) }) });
            if (!tlsResponse.ok) return showToast(await responseError(tlsResponse, 'errorAcme'), true, 0);
          }
          imported += 1;
        }
        if (credentials.length) downloadJson(`linklake-${type}-import-credentials.json`, { generated_at: new Date().toISOString(), credentials });
        showToast(t('importCompleted', { count: imported }));
        await loadManagementData({ forceHistory: false });
      }

      function renderAcme() {
        const config = state.dashboard.acme;
        let form = elements.acme_page.querySelector('form');
        let preserved = null;
        if (form && form.dataset.language !== state.language) {
          preserved = form.dataset.dirty === 'true' ? {
            enabled: form.elements.enabled.checked,
            environment: form.elements.environment.value,
            directory_url: form.elements.directory_url.value,
            contact_email: form.elements.contact_email.value,
            renew_before_days: form.elements.renew_before_days.value,
            terms_accepted: form.elements.terms_accepted.checked
          } : null;
          elements.acme_page.replaceChildren();
          form = null;
        }
        if (!form) {
          const card = document.createElement('section');
          card.className = 'acme-card';
          const status = document.createElement('p');
          status.id = 'acme-status';
          form = document.createElement('form');
          form.innerHTML = `
            <label class="check-label full"><input name="enabled" type="checkbox" /><span>${t('acmeEnabled')}</span></label>
            <label><span>${t('acmeEnvironment')}</span><select name="environment"><option value="staging">${t('acmeStaging')}</option><option value="production">${t('acmeProduction')}</option><option value="custom">${t('acmeCustom')}</option></select></label>
            <label><span>${t('renewBefore')}</span><input name="renew_before_days" type="number" min="7" max="60" required /></label>
            <label class="full"><span>${t('acmeDirectory')}</span><input name="directory_url" type="url" required /></label>
            <label class="full"><span>${t('acmeEmail')}</span><input name="contact_email" type="email" /></label>
            <label class="check-label full"><input name="terms_accepted" type="checkbox" /><span>${t('acmeTerms')}</span></label>
            <div class="inline-actions full"><button class="primary-button" type="submit">${t('saveAcme')}</button></div>`;
          form.addEventListener('input', () => { form.dataset.dirty = 'true'; updateAcmeDirectory(form); });
          form.addEventListener('submit', saveAcme);
          form.dataset.language = state.language;
          card.append(status, form);
          elements.acme_page.replaceChildren(card);
        }
        const status = elements.acme_page.querySelector('#acme-status');
        status.textContent = !config.enabled ? t('acmeOff') : config.account_registered ? t('acmeReady') : t('acmePending');
        if (preserved) {
          form.dataset.dirty = 'true';
          form.elements.enabled.checked = preserved.enabled;
          form.elements.environment.value = preserved.environment;
          form.elements.directory_url.value = preserved.directory_url;
          form.elements.contact_email.value = preserved.contact_email;
          form.elements.renew_before_days.value = preserved.renew_before_days;
          form.elements.terms_accepted.checked = preserved.terms_accepted;
        } else if (form.dataset.dirty !== 'true' && !form.contains(document.activeElement)) {
          form.elements.enabled.checked = Boolean(config.enabled);
          form.elements.environment.value = config.environment || 'staging';
          form.elements.directory_url.value = config.directory_url || acmeDirectories[config.environment] || '';
          form.elements.contact_email.value = config.contact_email || '';
          form.elements.renew_before_days.value = config.renew_before_days || 30;
          form.elements.terms_accepted.checked = Boolean(config.terms_accepted);
        }
        updateAcmeDirectory(form);
      }

      function clientIsOnline(client) {
        return Boolean(client.enabled) && Date.now() / 1000 - Number(client.last_seen_unix_seconds || 0) <= 120;
      }

      function clientConfigText(client) {
        const mode = { local: 'localConfig', report_only: 'reportOnlyConfig', server_managed: 'managedConfig' }[client.config_mode] || 'localConfig';
        const status = { synchronized: 'synchronized', conflict: 'conflict', apply_failed: 'applyFailed', unknown: 'unknownConfig' }[client.config_sync_status] || 'unknownConfig';
        return `${t(mode)} · ${t(status)}`;
      }

      function openClientModal(client) {
        state.clientEditorId = client.client_id;
        elements.client_modal_id.textContent = client.client_id;
        elements.client_name.value = client.name || '';
        elements.client_group.value = client.group_name || '';
        elements.client_tags.value = (client.tags || []).join(', ');
        elements.client_notes.value = client.notes || '';
        elements.client_enabled.checked = Boolean(client.enabled);
        elements.client_modal.classList.remove('hidden');
        requestAnimationFrame(() => elements.client_name.focus());
      }

      function closeClientModal() {
        elements.client_modal.classList.add('hidden');
        elements.client_form.reset();
        state.clientEditorId = null;
      }

      function clientUpdateBody(client, enabled = client.enabled) {
        return {
          name: client.name,
          group_name: client.group_name || null,
          tags: client.tags || [],
          notes: client.notes || null,
          enabled: Boolean(enabled)
        };
      }

      async function updateClientRequest(clientId, body) {
        const response = await apiFetch(`/api/v1/clients/${encodeURIComponent(clientId)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          showToast(payload.error || t('requestFailed'), true);
          return false;
        }
        return true;
      }

      async function submitClient(event) {
        event.preventDefault();
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        try {
          const tags = elements.client_tags.value.split(',').map(value => value.trim()).filter(Boolean);
          const updated = await updateClientRequest(state.clientEditorId, {
            name: elements.client_name.value.trim(),
            group_name: elements.client_group.value.trim() || null,
            tags,
            notes: elements.client_notes.value.trim() || null,
            enabled: elements.client_enabled.checked
          });
          if (!updated) return;
          closeClientModal();
          showToast(t('clientUpdated'));
          await loadManagementData({ forceHistory: false });
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function setClientEnabled(client) {
        const updated = await updateClientRequest(client.client_id, clientUpdateBody(client, !client.enabled));
        if (!updated) return;
        showToast(t('clientUpdated'));
        await loadManagementData({ forceHistory: false });
      }

      async function rotateClientToken(client) {
        if (!confirm(t('confirmTokenRotation', { name: client.name }))) return;
        const response = await apiFetch(`/api/v1/clients/${encodeURIComponent(client.client_id)}/rotate-token`, { method: 'POST' });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          return showToast(payload.error || t('requestFailed'), true);
        }
        const payload = await response.json();
        elements.client_token_value.value = payload.client_token;
        elements.client_token_modal.classList.remove('hidden');
        showToast(t('tokenRotated'));
      }

      function closeClientTokenModal() {
        elements.client_token_modal.classList.add('hidden');
        elements.client_token_value.value = '';
      }

      async function copyClientToken() {
        try {
          await navigator.clipboard.writeText(elements.client_token_value.value);
          showToast(t('tokenCopied'));
        } catch (_) {
          elements.client_token_value.focus();
          elements.client_token_value.select();
          showToast(t('clientToken'));
        }
      }

      async function deleteClient(client) {
        if (!confirm(t('confirmClientDelete', { name: client.name }))) return;
        const response = await apiFetch(`/api/v1/clients/${encodeURIComponent(client.client_id)}`, { method: 'DELETE' });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          return showToast(payload.error || t('requestFailed'), true);
        }
        showToast(t('clientDeleted'));
        await loadManagementData({ forceHistory: false });
      }

      function clientLastSeenRelative(client) {
        const lastSeen = Number(client.last_seen_unix_seconds || 0);
        if (!lastSeen) return t('neverSeen');
        const elapsed = Math.max(0, Date.now() / 1000 - lastSeen);
        if (elapsed <= 120) return t('justNow');
        return t('seenAgo', { time: formatDuration(elapsed) });
      }

      function drawClientInsightCharts(visibleClients = state.visibleClients || []) {
        const enabled = visibleClients.filter(client => client.enabled).length;
        const online = visibleClients.filter(clientIsOnline).length;
        drawBarChart(elements.client_status_chart, [
          { label: t('online'), value: online, color: '--success' },
          { label: t('offline'), value: Math.max(0, enabled - online), color: '--warning' },
          { label: t('disabled'), value: Math.max(0, visibleClients.length - enabled), color: '--faint' }
        ], true);
        const platformCounts = new Map();
        visibleClients.forEach(client => {
          const platform = client.platform || t('unknown');
          platformCounts.set(platform, (platformCounts.get(platform) || 0) + 1);
        });
        const sortedPlatforms = [...platformCounts.entries()].sort((left, right) => right[1] - left[1]);
        const platformItems = sortedPlatforms.slice(0, 3).map(([label, value]) => ({ label, value }));
        const otherPlatforms = sortedPlatforms.slice(3).reduce((total, [, value]) => total + value, 0);
        if (otherPlatforms) platformItems.push({ label: t('other'), value: otherPlatforms });
        const configModes = [
          { label: t('managedConfig'), value: visibleClients.filter(client => client.config_mode === 'server_managed').length },
          { label: t('reportOnlyConfig'), value: visibleClients.filter(client => client.config_mode === 'report_only').length },
          { label: t('localConfig'), value: visibleClients.filter(client => !client.config_mode || client.config_mode === 'local').length }
        ];
        drawGroupedHorizontalChart(elements.client_platform_chart, [
          { label: t('platform'), items: platformItems },
          { label: t('configStatus'), items: configModes }
        ]);
      }

      function renderClientInsights(visibleClients) {
        state.visibleClients = visibleClients;
        const enabled = visibleClients.filter(client => client.enabled).length;
        const online = visibleClients.filter(clientIsOnline).length;
        const issues = visibleClients.filter(client => client.config_sync_status === 'conflict' || client.config_sync_status === 'apply_failed').length;
        const platforms = new Set(visibleClients.map(client => client.platform || t('unknown')));
        elements.client_insight_kpis.replaceChildren(
          createInsightKpi(String(visibleClients.length), t('clients')),
          createInsightKpi(String(online), t('online')),
          createInsightKpi(String(Math.max(0, enabled - online)), t('offline')),
          createInsightKpi(String(issues), t('configIssues')),
          createInsightKpi(String(platforms.size), t('platforms'))
        );
        drawClientInsightCharts(visibleClients);
      }

      function renderClients() {
        const clients = state.dashboard.clients || [];
        const query = state.clientSearch.trim().toLowerCase();
        const visible = clients.filter(client => {
          const online = clientIsOnline(client);
          if (state.clientStatus === 'online' && !online) return false;
          if (state.clientStatus === 'offline' && online) return false;
          if (state.clientStatus === 'enabled' && !client.enabled) return false;
          if (state.clientStatus === 'disabled' && client.enabled) return false;
          const text = [client.name, client.client_id, client.platform, client.group_name, ...(client.tags || []), client.notes].filter(Boolean).join(' ').toLowerCase();
          return !query || text.includes(query);
        });
        renderClientInsights(visible);
        elements.client_count.textContent = t('clientCount', { visible: visible.length, total: clients.length });
        elements.clients_list.replaceChildren();
        visible.forEach(client => {
          const row = document.createElement('tr');
          const online = clientIsOnline(client);
          const status = !client.enabled ? t('disabled') : online ? t('online') : t('offline');
          [client.name, client.group_name || '—', (client.tags || []).join(', ') || '—', client.platform].forEach(value => {
            const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
          });
          const statusCell = document.createElement('td');
          const presence = document.createElement('span');
          presence.className = `client-presence ${!client.enabled ? 'disabled' : online ? 'online' : 'offline'}`;
          const presenceLabel = document.createElement('strong');
          const presenceDot = document.createElement('i'); presenceDot.setAttribute('aria-hidden', 'true');
          presenceLabel.append(presenceDot, document.createTextNode(status));
          presence.append(presenceLabel);
          statusCell.append(presence);
          const lastSeenCell = document.createElement('td');
          lastSeenCell.className = 'cell-stack';
          const lastSeenValue = document.createElement('span'); lastSeenValue.textContent = formatTimestamp(client.last_seen_unix_seconds);
          const lastSeenRelative = document.createElement('small'); lastSeenRelative.textContent = clientLastSeenRelative(client);
          lastSeenCell.append(lastSeenValue, lastSeenRelative);
          const configCell = document.createElement('td'); configCell.textContent = clientConfigText(client);
          row.append(statusCell, lastSeenCell, configCell);
          const actions = document.createElement('td'); actions.className = 'table-actions';
          if (state.identity.role !== 'auditor') {
            const edit = actionButton(t('editClient'), () => openClientModal(client));
            const enabled = actionButton(client.enabled ? t('revoke') : t('enable'), () => setClientEnabled(client));
            const rotate = actionButton(t('rotateToken'), () => rotateClientToken(client));
            const remove = actionButton(t('delete'), () => deleteClient(client), 'danger-button');
            remove.disabled = online;
            actions.append(edit, enabled, rotate, remove);
          }
          row.append(actions);
          elements.clients_list.append(row);
        });
      }

      function updateAcmeDirectory(form) {
        const environment = form.elements.environment.value;
        const input = form.elements.directory_url;
        input.readOnly = environment !== 'custom';
        if (environment !== 'custom') input.value = acmeDirectories[environment] || '';
      }

      function renderP2p() {
        const dashboard = state.dashboard;
        elements.p2p_list.replaceChildren();
        if (!dashboard.p2pNodes.length) {
          const empty = document.createElement('div'); empty.className = 'empty-state'; empty.textContent = t('noP2pNodes'); elements.p2p_list.append(empty); return;
        }
        dashboard.p2pNodes.forEach(node => {
          const card = document.createElement('article');
          card.className = 'p2p-card';
          const heading = document.createElement('h3');
          const name = document.createElement('span');
          const badge = document.createElement('span');
          name.textContent = clientName(node.client_id);
          badge.className = `badge ${node.fresh ? 'online' : 'warning'}`;
          badge.textContent = node.fresh ? t('p2pFresh') : t('p2pStale');
          heading.append(name, badge);
          const id = document.createElement('p'); id.textContent = node.client_id;
          const age = document.createElement('p'); age.textContent = `${t('age')}: ${node.age_seconds}s`;
          const candidates = document.createElement('div'); candidates.className = 'candidate-list';
          (node.candidates || []).forEach(candidate => {
            const item = document.createElement('div'); item.className = 'candidate';
            if (candidate.transport === 'iroh_quic') {
              try {
                const parsed = JSON.parse(candidate.endpoint);
                const network = parsed.network || {};
                item.textContent = `${candidate.transport} · ${(parsed.direct_addresses || []).join(' · ')} · ${t('mapping')}: ${network.mapping_behavior || t('unknown')} · ${t('portMapping')}: ${network.port_mapping ? 'yes' : 'no'} · ${t('rendezvous')}: ${parsed.relay_url || t('unknown')}`;
              } catch (_) { item.textContent = `${candidate.transport} · ${candidate.endpoint}`; }
            } else item.textContent = `${candidate.transport} · ${candidate.endpoint}`;
            candidates.append(item);
          });
          card.append(heading, id, age, candidates);
          elements.p2p_list.append(card);
        });
      }

      function renderFleet() {
        const overview = state.dashboard.fleetOverview || { peers: [], conflicts: [], failover_order: [] };
        const peers = overview.peers || [];
        const dnsFailovers = overview.dns_failovers || [];
        const healthMetrics = overview.health_metrics || {};
        const preferred = peers.find(peer => peer.id === overview.preferred_peer_id);
        const frozenDns = dnsFailovers.filter(item => item.frozen).length;
        const dnsText = state.language === 'zh'
          ? { title: 'DNS 故障切换', frozen: '已冻结', manualFreeze: '手动冻结', failed: '最近更新失败', waiting: '等待健康节点', never: '尚未切换' }
          : { title: 'DNS failover', frozen: 'frozen', manualFreeze: 'manual freeze', failed: 'Last update failed', waiting: 'Waiting for an eligible peer', never: 'not switched' };
        elements.fleet_summary.replaceChildren(
          createKpi(String(healthMetrics.fleet_peers_healthy ?? peers.filter(peer => peer.online).length), t('onlineServers'), `${peers.length} ${t('total')}`),
          createKpi(preferred?.name || '—', t('preferredEntry'), preferred?.region || ''),
          createKpi(String((overview.failover_order || []).length), t('failoverEntries')),
          createKpi(formatBytes(peers.reduce((sum, peer) => sum + Number(peer.bytes_total || 0), 0)), t('traffic')),
          createKpi(String(dnsFailovers.length), dnsText.title, `${frozenDns} ${dnsText.frozen}`)
        );
        elements.fleet_conflicts.replaceChildren();
        (overview.conflicts || []).forEach(message => {
          const item = document.createElement('div');
          item.className = 'alert-item warning';
          const strong = document.createElement('strong'); strong.textContent = t('fleetConflict');
          const detail = document.createElement('span'); detail.textContent = message;
          item.append(strong, detail);
          elements.fleet_conflicts.append(item);
        });
        dnsFailovers.forEach(failover => {
          const item = document.createElement('div');
          item.className = `alert-item ${(failover.frozen || failover.last_error_summary) ? 'warning' : 'info'}`;
          const strong = document.createElement('strong'); strong.textContent = `${failover.hostname} · ${failover.record_type}`;
          const detail = document.createElement('span');
          detail.textContent = failover.frozen
            ? `${dnsText.frozen}: ${failover.freeze_reason || dnsText.manualFreeze}`
            : failover.last_error_summary
              ? `${dnsText.failed}: ${failover.last_error_summary}`
              : `${failover.current_target || dnsText.waiting} · ${failover.last_switch_reason || dnsText.never}`;
          item.append(strong, detail);
          elements.fleet_conflicts.append(item);
        });
        elements.fleet_list.replaceChildren();
        if (!peers.length) {
          const row = document.createElement('tr');
          const cell = document.createElement('td'); cell.colSpan = 8; cell.textContent = t('noFleetPeers');
          row.append(cell); elements.fleet_list.append(row); return;
        }
        peers.forEach(peer => {
          const row = document.createElement('tr');
          const healthState = peer.health?.state || 'unknown';
          const healthLabels = state.language === 'zh'
            ? { unknown: '未知', healthy: '健康', degraded: '降级', unhealthy: '不健康', recovering: '恢复中' }
            : { unknown: 'Unknown', healthy: 'Healthy', degraded: 'Degraded', unhealthy: 'Unhealthy', recovering: 'Recovering' };
          const status = !peer.enabled ? t('disabled') : (healthLabels[healthState] || healthState);
          [peer.name, peer.region, status, peer.latency_millis == null ? '—' : `${peer.latency_millis} ms`, String(peer.priority), String(peer.weight), formatBytes(peer.bytes_total)].forEach(value => {
            const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
          });
          row.children[2].title = `${peer.health?.last_transition_reason || ''} · success ${peer.health?.consecutive_successes || 0}/${peer.health_config?.success_threshold || 0} · failure ${peer.health?.consecutive_failures || 0}/${peer.health_config?.failure_threshold || 0} · cooldown ${peer.health_config?.cooldown_seconds || 0}s`;
          const actions = document.createElement('td'); actions.className = 'table-actions';
          actions.append(actionButton(t('editPolicy'), () => openFleetModal(peer)), actionButton(t('delete'), () => deleteFleetPeer(peer), 'danger-button'));
          row.append(actions); elements.fleet_list.append(row);
        });
      }

      function openFleetModal(peer = null) {
        state.fleetEditorId = peer?.id || null;
        elements.fleet_modal_title.textContent = peer ? t('editFleetPeer') : t('newFleetPeer');
        elements.fleet_name.value = peer?.name || '';
        elements.fleet_url.value = peer?.url || 'https://';
        elements.fleet_region.value = peer?.region || '';
        elements.fleet_token_env.value = peer?.token_env || 'LINKLAKE_FLEET_TOKEN';
        elements.fleet_priority.value = peer?.priority ?? 100;
        elements.fleet_weight.value = peer?.weight ?? 100;
        elements.fleet_enabled.checked = peer?.enabled ?? true;
        elements.fleet_modal.classList.remove('hidden');
        requestAnimationFrame(() => elements.fleet_name.focus());
      }

      function closeFleetModal() {
        elements.fleet_modal.classList.add('hidden');
        elements.fleet_form.reset();
        state.fleetEditorId = null;
      }

      async function submitFleetPeer(event) {
        event.preventDefault();
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        const body = { name: elements.fleet_name.value.trim(), url: elements.fleet_url.value.trim(), region: elements.fleet_region.value.trim(), token_env: elements.fleet_token_env.value.trim(), priority: Number(elements.fleet_priority.value), weight: Number(elements.fleet_weight.value), enabled: elements.fleet_enabled.checked };
        try {
          const response = await apiFetch(state.fleetEditorId ? `/api/v1/fleet/peers/${encodeURIComponent(state.fleetEditorId)}` : '/api/v1/fleet/peers', { method: state.fleetEditorId ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          if (!response.ok) return showToast(await responseError(response), true);
          closeFleetModal(); showToast(t('fleetSaved')); await loadManagementData({ forceHistory: false });
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function deleteFleetPeer(peer) {
        if (!confirm(t('confirmFleetDelete', { name: peer.name }))) return;
        const response = await apiFetch(`/api/v1/fleet/peers/${encodeURIComponent(peer.id)}`, { method: 'DELETE' });
        if (!response.ok) return showToast(await responseError(response), true);
        showToast(t('fleetDeleted')); await loadManagementData({ forceHistory: false });
      }

      async function runFleetSync(dryRun, button) {
        if (!dryRun && !confirm(t('applyFleetSync'))) return;
        setBusy(button, true, dryRun ? 'previewFleetSync' : 'applyFleetSync');
        try {
          const response = await apiFetch('/api/v1/fleet/sync', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dry_run: dryRun }) });
          if (!response.ok) return showToast(await responseError(response), true);
          const results = await response.json();
          elements.fleet_conflicts.replaceChildren();
          for (const result of results) {
            const item = document.createElement('div');
            item.className = `alert-item ${(result.error || result.conflicts?.length) ? 'warning' : 'info'}`;
            item.textContent = `${result.peer_name}: created ${result.created}, unchanged ${result.unchanged}${result.conflicts?.length ? `, conflicts ${result.conflicts.join(' | ')}` : ''}${result.error ? `, error ${result.error}` : ''}`;
            elements.fleet_conflicts.append(item);
          }
          showToast(t(dryRun ? 'fleetSyncPreviewed' : 'fleetSyncApplied'));
          if (!dryRun) await loadManagementData({ forceHistory: false });
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(button, false); }
      }

      function trafficKind(type) {
        return type === 'ports' ? 'port_group' : type === 'http-proxy' ? 'http_proxy' : type;
      }

      function minuteToTime(value) {
        if (value == null) return '';
        return `${String(Math.floor(value / 60)).padStart(2, '0')}:${String(value % 60).padStart(2, '0')}`;
      }

      function timeToMinute(value) {
        if (!value) return null;
        const [hour, minute] = value.split(':').map(Number);
        return hour * 60 + minute;
      }

      async function openTrafficControl(type, policy) {
        state.trafficEditor = { type, policyId: policy.id };
        let control = null;
        const response = await apiFetch(`/api/v1/traffic-controls/${trafficKind(type)}/${encodeURIComponent(policy.id)}`);
        if (response.ok) control = await response.json();
        else if (response.status !== 404) return showToast(await responseError(response), true);
        elements.traffic_allowed.value = (control?.allowed_cidrs || []).join('\n');
        elements.traffic_denied.value = (control?.denied_cidrs || []).join('\n');
        elements.traffic_rate.value = control?.max_connections_per_minute ?? '';
        elements.traffic_quota.value = control?.daily_quota_bytes ? Math.ceil(control.daily_quota_bytes / 1048576) : '';
        elements.traffic_weekdays.value = (control?.active_weekdays_utc || []).join(',');
        elements.traffic_start.value = minuteToTime(control?.start_minute_utc);
        elements.traffic_end.value = minuteToTime(control?.end_minute_utc);
        elements.traffic_enabled.checked = control?.enabled ?? true;
        elements.traffic_usage.textContent = t('usageToday', { value: formatBytes(control?.used_today_bytes || 0) });
        elements.traffic_control_modal.classList.remove('hidden');
      }

      function closeTrafficControl() {
        elements.traffic_control_modal.classList.add('hidden');
        elements.traffic_control_form.reset();
        state.trafficEditor = null;
      }

      function splitList(value) {
        return value.split(/[\s,]+/).map(item => item.trim()).filter(Boolean);
      }

      async function submitTrafficControl(event) {
        event.preventDefault();
        if (!state.trafficEditor) return;
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        const quotaMiB = Number(elements.traffic_quota.value || 0);
        const body = {
          allowed_cidrs: splitList(elements.traffic_allowed.value),
          denied_cidrs: splitList(elements.traffic_denied.value),
          max_connections_per_minute: elements.traffic_rate.value ? Number(elements.traffic_rate.value) : null,
          daily_quota_bytes: quotaMiB > 0 ? quotaMiB * 1048576 : null,
          active_weekdays_utc: splitList(elements.traffic_weekdays.value).map(Number),
          start_minute_utc: timeToMinute(elements.traffic_start.value),
          end_minute_utc: timeToMinute(elements.traffic_end.value),
          enabled: elements.traffic_enabled.checked
        };
        try {
          const response = await apiFetch(`/api/v1/traffic-controls/${trafficKind(state.trafficEditor.type)}/${encodeURIComponent(state.trafficEditor.policyId)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          if (!response.ok) return showToast(await responseError(response), true);
          closeTrafficControl(); showToast(t('trafficControlSaved'));
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      function roleText(role) {
        return t({ administrator: 'roleAdministrator', operator: 'roleOperator', auditor: 'roleAuditor' }[role] || 'roleAuditor');
      }

      function openUserModal(user = null) {
        state.userEditor = { mode: user ? 'edit' : 'create', username: user?.username || null };
        const enabledAdministrators = (state.dashboard.users || []).filter(item => item.enabled && item.role === 'administrator').length;
        const protectedAdministrator = Boolean(user && user.enabled && user.role === 'administrator' && enabledAdministrators <= 1);
        const currentUser = user?.username === state.identity.username;
        elements.user_modal_title.textContent = user ? t('editPolicy') : t('newUser');
        elements.user_username.disabled = Boolean(user);
        elements.user_username.value = user?.username || '';
        elements.user_display_name.value = user?.display_name || '';
        elements.user_role.value = user?.role || 'operator';
        elements.user_role.disabled = currentUser || protectedAdministrator;
        elements.user_password.value = '';
        elements.user_password.required = !user;
        elements.user_password_label.classList.toggle('hidden', Boolean(user));
        elements.user_enabled_label.classList.toggle('hidden', !user);
        elements.user_enabled.checked = user?.enabled ?? true;
        elements.user_enabled.disabled = currentUser || protectedAdministrator;
        elements.user_force_change_label.classList.toggle('hidden', Boolean(user));
        elements.user_force_change.checked = true;
        elements.user_modal.classList.remove('hidden');
        requestAnimationFrame(() => (user ? elements.user_display_name : elements.user_username).focus());
      }

      function closeUserModal() {
        elements.user_modal.classList.add('hidden');
        elements.user_form.reset();
      }

      async function refreshUsers() {
        const response = await apiFetch('/api/v1/users', { headers: { Accept: 'application/json' }, scope: 'user-management' });
        if (!response.ok) {
          showToast(await responseError(response, 'requestFailed'), true);
          return false;
        }
        const users = await response.json();
        state.dashboard ||= emptyDashboard();
        state.dashboard.users = Array.isArray(users) ? users : [];
        if (state.route.view === 'users') renderUsers();
        return true;
      }

      async function submitUser(event) {
        event.preventDefault();
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        const editing = state.userEditor.mode === 'edit';
        const username = state.userEditor.username || elements.user_username.value.trim();
        const body = editing
          ? { display_name: elements.user_display_name.value.trim(), role: elements.user_role.value, enabled: elements.user_enabled.checked }
          : { username, display_name: elements.user_display_name.value.trim(), role: elements.user_role.value, password: elements.user_password.value, force_password_change: elements.user_force_change.checked };
        try {
          const response = await apiFetch(editing ? `/api/v1/users/${encodeURIComponent(username)}` : '/api/v1/users', { method: editing ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            return showToast(payload.error || t('requestFailed'), true);
          }
          closeUserModal();
          showToast(t(editing ? 'userUpdated' : 'userCreated'));
          await refreshUsers();
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function deleteUser(user) {
        if (!confirm(t('confirmUserDelete', { username: user.username }))) return;
        const response = await apiFetch(`/api/v1/users/${encodeURIComponent(user.username)}`, { method: 'DELETE' });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          return showToast(payload.error || t('requestFailed'), true);
        }
        showToast(t('userDeleted'));
        await refreshUsers();
      }

      function openResetPassword(user) {
        state.resetUsername = user.username;
        elements.reset_password_value.value = '';
        elements.reset_force_change.checked = true;
        elements.reset_password_modal.classList.remove('hidden');
        requestAnimationFrame(() => elements.reset_password_value.focus());
      }

      function closeResetPassword() {
        elements.reset_password_modal.classList.add('hidden');
        elements.reset_password_form.reset();
        state.resetUsername = null;
      }

      async function submitResetPassword(event) {
        event.preventDefault();
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        try {
          const response = await apiFetch(`/api/v1/users/${encodeURIComponent(state.resetUsername)}/reset-password`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ new_password: elements.reset_password_value.value, force_password_change: elements.reset_force_change.checked }) });
          if (!response.ok) {
            const payload = await response.json().catch(() => ({}));
            return showToast(payload.error || t('requestFailed'), true);
          }
          closeResetPassword();
          showToast(t('passwordReset'));
          await refreshUsers();
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function revokeUserSessions(user) {
        if (!confirm(t('confirmRevokeSessions', { username: user.username }))) return;
        const response = await apiFetch(`/api/v1/users/${encodeURIComponent(user.username)}/revoke-sessions`, { method: 'POST' });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          return showToast(payload.error || t('requestFailed'), true);
        }
        showToast(t('sessionsRevoked'));
        if (user.username === state.identity.username) return resetForExpiredSession();
        await refreshUsers();
      }

      function renderUsers() {
        const users = state.dashboard.users || [];
        const query = state.userSearch.trim().toLowerCase();
        const visible = users.filter(user => {
          if (state.userRole !== 'all' && user.role !== state.userRole) return false;
          return !query || `${user.username} ${user.display_name}`.toLowerCase().includes(query);
        });
        elements.user_count.textContent = t('userCount', { visible: visible.length, total: users.length });
        elements.users_list.replaceChildren();
        visible.forEach(user => {
          const row = document.createElement('tr');
          const values = [user.username, user.display_name, roleText(user.role), user.enabled ? t('enabled') : t('disabled'), user.last_login_unix_seconds ? formatTimestamp(user.last_login_unix_seconds) : t('never'), `${user.active_sessions}${user.must_change_password ? ` · ${t('mustChangePassword')}` : ''}`];
          values.forEach(value => { const cell = document.createElement('td'); cell.textContent = value; row.append(cell); });
          const actions = document.createElement('td'); actions.className = 'table-actions';
          const edit = actionButton(t('editPolicy'), () => openUserModal(user));
          const reset = actionButton(t('resetPassword'), () => openResetPassword(user));
          const sessions = actionButton(t('revokeSessions'), () => revokeUserSessions(user));
          const remove = actionButton(t('delete'), () => deleteUser(user), 'danger-button');
          const enabledAdministrators = users.filter(item => item.enabled && item.role === 'administrator').length;
          remove.disabled = user.username === state.identity.username || (user.enabled && user.role === 'administrator' && enabledAdministrators <= 1);
          actions.append(edit, reset, sessions, remove);
          row.append(actions);
          elements.users_list.append(row);
        });
      }

      async function revokeSessionRecord(session) {
        if (!confirm(t('confirmRevokeSession'))) return;
        const response = await apiFetch(`/api/v1/sessions/${encodeURIComponent(session.session_id)}`, { method: 'DELETE' });
        if (!response.ok) {
          const payload = await response.json().catch(() => ({}));
          return showToast(payload.error || t('requestFailed'), true);
        }
        showToast(t('sessionsRevoked'));
        await loadManagementData({ forceHistory: false });
      }

      function renderSessions() {
        const sessions = state.dashboard.sessions || [];
        const tokens = state.dashboard.apiTokens || [];
        elements.totp_status.textContent = state.identity.totp_enabled ? t('totpEnabled') : t('totpDisabled');
        elements.totp_action.textContent = state.identity.totp_enabled ? t('disableTotp') : t('setupTotp');
        elements.api_tokens_list.replaceChildren();
        if (!tokens.length) {
          const row = document.createElement('tr');
          const cell = document.createElement('td');
          cell.colSpan = 6;
          cell.textContent = t('noApiTokens');
          row.append(cell);
          elements.api_tokens_list.append(row);
        }
        tokens.forEach(token => {
          const row = document.createElement('tr');
          const scopeKey = { read: 'scopeRead', write: 'scopeWrite', administrator: 'scopeAdministrator' }[token.scope] || 'scopeRead';
          [token.name, t(scopeKey), formatTimestamp(token.created_unix_seconds), token.expires_unix_seconds ? formatTimestamp(token.expires_unix_seconds) : t('never'), token.last_used_unix_seconds ? formatTimestamp(token.last_used_unix_seconds) : t('never')].forEach(value => {
            const cell = document.createElement('td');
            cell.textContent = value;
            row.append(cell);
          });
          const actions = document.createElement('td');
          actions.className = 'table-actions';
          actions.append(actionButton(t('revoke'), () => revokeApiToken(token), 'danger-button'));
          row.append(actions);
          elements.api_tokens_list.append(row);
        });
        elements.sessions_list.replaceChildren();
        sessions.forEach(session => {
          const row = document.createElement('tr');
          const current = session.session_id === state.identity.session_id;
          [session.username, `${session.session_id}${current ? ` · ${t('currentSession')}` : ''}`, session.remote_addr || '—', session.user_agent || '—', formatTimestamp(session.created_unix_seconds), formatTimestamp(session.expires_unix_seconds)].forEach(value => { const cell = document.createElement('td'); cell.textContent = value; row.append(cell); });
          const actions = document.createElement('td'); actions.className = 'table-actions';
          if (!current) actions.append(actionButton(t('revoke'), () => revokeSessionRecord(session), 'danger-button'));
          row.append(actions);
          elements.sessions_list.append(row);
        });
      }

      async function openTotpModal() {
        state.totpMode = state.identity.totp_enabled ? 'disable' : 'enable';
        elements.totp_form.reset();
        elements.totp_setup_fields.classList.toggle('hidden', state.totpMode !== 'enable');
        elements.totp_modal_help.textContent = t(state.totpMode === 'enable' ? 'totpSetupHelp' : 'totpDisableHelp');
        elements.totp_submit.textContent = t(state.totpMode === 'enable' ? 'enable' : 'disableTotp');
        if (state.totpMode === 'enable') {
          const response = await apiFetch('/api/v1/auth/totp/setup', { method: 'POST' });
          if (!response.ok) return showToast(await responseError(response), true);
          const setup = await response.json();
          elements.totp_secret.value = setup.secret;
          elements.totp_uri.value = setup.provisioning_uri;
        }
        elements.totp_modal.classList.remove('hidden');
        requestAnimationFrame(() => elements.totp_code.focus());
      }

      function closeTotpModal() {
        elements.totp_modal.classList.add('hidden');
        elements.totp_form.reset();
        elements.totp_secret.value = '';
        elements.totp_uri.value = '';
      }

      async function submitTotp(event) {
        event.preventDefault();
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        try {
          const operation = state.totpMode === 'enable' ? 'enable' : 'disable';
          const response = await apiFetch(`/api/v1/auth/totp/${operation}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: elements.totp_code.value }) });
          if (!response.ok) return showToast(t('invalidTotp'), true);
          closeTotpModal();
          const identityResponse = await apiFetch('/api/v1/auth/me');
          if (!identityResponse.ok) return;
          state.identity = await identityResponse.json();
          updateIdentityUi();
          renderSessions();
          showToast(t(operation === 'enable' ? 'totpEnabledMessage' : 'totpDisabledMessage'));
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      function openApiTokenModal() {
        elements.api_token_form.reset();
        elements.api_token_fields.classList.remove('hidden');
        elements.api_token_value_label.classList.add('hidden');
        elements.api_token_submit.classList.remove('hidden');
        elements.api_token_copy.classList.add('hidden');
        elements.api_token_modal.classList.remove('hidden');
        requestAnimationFrame(() => elements.api_token_name.focus());
      }

      function closeApiTokenModal() {
        elements.api_token_modal.classList.add('hidden');
        elements.api_token_form.reset();
        elements.api_token_value.value = '';
      }

      async function submitApiToken(event) {
        event.preventDefault();
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        try {
          const days = Number(elements.api_token_expiry.value || 0);
          const response = await apiFetch('/api/v1/api-tokens', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: elements.api_token_name.value.trim(), scope: elements.api_token_scope.value, expires_unix_seconds: days > 0 ? Math.floor(Date.now() / 1000) + days * 86400 : null }) });
          if (!response.ok) return showToast(await responseError(response), true);
          const created = await response.json();
          elements.api_token_value.value = created.token;
          elements.api_token_fields.classList.add('hidden');
          elements.api_token_value_label.classList.remove('hidden');
          elements.api_token_submit.classList.add('hidden');
          elements.api_token_copy.classList.remove('hidden');
          showToast(t('apiTokenCreated'));
          await loadManagementData({ forceHistory: false });
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function copyApiToken() {
        await navigator.clipboard.writeText(elements.api_token_value.value);
        showToast(t('tokenCopied'));
      }

      async function revokeApiToken(token) {
        if (!confirm(t('confirmApiTokenRevoke', { name: token.name }))) return;
        const response = await apiFetch(`/api/v1/api-tokens/${encodeURIComponent(token.id)}`, { method: 'DELETE' });
        if (!response.ok) return showToast(await responseError(response), true);
        showToast(t('apiTokenRevoked'));
        await loadManagementData({ forceHistory: false });
      }

      function alertMetricText(metric) {
        return t({
          client_offline: 'metricClientOffline', policy_unavailable: 'metricPolicyUnavailable', authentication_failures: 'metricAuthenticationFailures', traffic_bytes_per_second: 'metricTrafficRate', active_connections: 'metricActiveConnections', certificate_days_remaining: 'metricCertificateDays', slo_fast_burn_rate: 'metricSloFastBurn', slo_slow_burn_rate: 'metricSloSlowBurn'
        }[metric] || 'alertMetric');
      }

      function alertSeverityText(severity) {
        return t({ info: 'severityInfo', warning: 'severityWarning', critical: 'severityCritical' }[severity] || 'severityWarning');
      }

      function openAlertRuleModal(rule = null) {
        state.alertEditorId = rule?.id || null;
        elements.alert_rule_title.textContent = rule ? t('editAlertRule') : t('newAlertRule');
        elements.alert_rule_name.value = rule?.name || '';
        elements.alert_rule_metric.value = rule?.metric || 'client_offline';
        elements.alert_rule_comparator.value = rule?.comparator || 'greater_or_equal';
        elements.alert_rule_threshold.value = rule?.threshold ?? 1;
        elements.alert_rule_target.value = rule?.target || '';
        elements.alert_rule_window.value = rule?.evaluation_window_seconds ?? 300;
        elements.alert_rule_cooldown.value = rule?.cooldown_seconds ?? 900;
        elements.alert_rule_severity.value = rule?.severity || 'warning';
        elements.alert_rule_enabled.checked = rule?.enabled ?? true;
        elements.alert_rule_webhook.checked = rule?.notify_webhook ?? false;
        elements.alert_rule_email.checked = rule?.notify_email ?? false;
        elements.alert_rule_modal.classList.remove('hidden');
        requestAnimationFrame(() => elements.alert_rule_name.focus());
      }

      function closeAlertRuleModal() {
        elements.alert_rule_modal.classList.add('hidden');
        elements.alert_rule_form.reset();
        state.alertEditorId = null;
      }

      async function submitAlertRule(event) {
        event.preventDefault();
        const submit = event.submitter;
        setBusy(submit, true, 'saving');
        const body = {
          name: elements.alert_rule_name.value.trim(), metric: elements.alert_rule_metric.value, comparator: elements.alert_rule_comparator.value, threshold: Number(elements.alert_rule_threshold.value), target: elements.alert_rule_target.value.trim() || null, evaluation_window_seconds: Number(elements.alert_rule_window.value), cooldown_seconds: Number(elements.alert_rule_cooldown.value), severity: elements.alert_rule_severity.value, notify_webhook: elements.alert_rule_webhook.checked, notify_email: elements.alert_rule_email.checked, enabled: elements.alert_rule_enabled.checked
        };
        try {
          const editing = Boolean(state.alertEditorId);
          const response = await apiFetch(editing ? `/api/v1/alerts/rules/${encodeURIComponent(state.alertEditorId)}` : '/api/v1/alerts/rules', { method: editing ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
          if (!response.ok) return showToast(await responseError(response), true);
          closeAlertRuleModal();
          showToast(t('alertRuleSaved'));
          await loadManagementData({ forceHistory: false });
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function deleteAlertRule(rule) {
        if (!confirm(t('confirmDeleteAlertRule'))) return;
        const response = await apiFetch(`/api/v1/alerts/rules/${encodeURIComponent(rule.id)}`, { method: 'DELETE' });
        if (!response.ok) return showToast(await responseError(response), true);
        showToast(t('alertRuleDeleted'));
        await loadManagementData({ forceHistory: false });
      }

      function appendUpdateDetail(parent, label, value) {
        const row = document.createElement('div');
        row.className = 'update-detail';
        const name = document.createElement('span'); name.textContent = label;
        const content = document.createElement('strong'); content.textContent = value || '—';
        row.append(name, content);
        parent.append(row);
      }

      function updateStateText(status, operationActive = false) {
        const stateName = String(status?.state || 'idle');
        if (stateName === 'failed' || status?.has_error) return t('updateFailed');
        if (stateName === 'succeeded') return t('updateSucceeded');
        if (stateName === 'rolled_back') return t('updateRolledBack');
        if (operationActive || ['scheduled', 'installing', 'waiting', 'applying', 'replacing', 'validating', 'rolling_back'].includes(stateName)) return t('updateBusy');
        return t('updateIdle');
      }

      function updateOperationBusy(status, operationActive = false) {
        return Boolean(operationActive) || ['scheduled', 'installing', 'waiting', 'applying', 'replacing', 'validating', 'rolling_back'].includes(String(status?.state || 'idle'));
      }

      function updateStatusMessage(status, operationActive = false) {
        if (operationActive && (!status || status.state === 'idle')) return t('updateBusy');
        if (!status || status.state === 'idle') return t('noUpdateScheduled');
        return status.message || updateStateText(status, operationActive);
      }

      function renderServerUpdateRelease(check) {
        elements.server_update_release.replaceChildren();
        elements.server_update_release.classList.toggle('hidden', !check);
        if (!check) return;
        const heading = document.createElement('strong');
        heading.textContent = `${t('releaseDetails')}: ${check.latest_version || '—'} · ${check.update_available ? t('updateAvailable') : t('upToDate')}`;
        const asset = document.createElement('span'); asset.textContent = check.asset_name || '';
        const key = document.createElement('span'); key.textContent = `${t('signingKey')}: ${check.signature_key_id || '—'}`;
        const digest = document.createElement('span'); digest.textContent = `${t('packageDigest')}: ${check.github_digest || '—'}`;
        elements.server_update_release.append(heading, asset, key, digest);
        try {
          const release = new URL(check.release_url);
          if (release.protocol === 'https:' && release.hostname === 'github.com') {
            const link = document.createElement('a'); link.href = release.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = release.href;
            elements.server_update_release.append(link);
          }
        } catch (_) {}
      }

      function renderUpdateCenter() {
        const overview = state.dashboard?.updateOverview;
        const status = overview?.status || { state: 'idle' };
        const busy = updateOperationBusy(status, overview?.operation_active);
        elements.update_kpis.replaceChildren(
          createKpi(overview?.build?.version || '—', t('installedVersion')),
          createKpi(updateStateText(status, overview?.operation_active), t('updateState'), updateStatusMessage(status, overview?.operation_active)),
          createKpi(t('stableChannel'), t('releaseChannel')),
          createKpi(overview?.signature_policy === 'production' ? t('production') : '—', t('signaturePolicy')),
          createKpi(overview?.remote_client_update_available ? t('enabled') : t('localOnly'), t('clientUpdate'))
        );
        elements.server_update_state.textContent = updateStateText(status, overview?.operation_active);
        elements.server_update_state.classList.toggle('warning', status.state === 'failed' || status.has_error || busy);
        elements.server_update_details.replaceChildren();
        appendUpdateDetail(elements.server_update_details, t('installedVersion'), overview?.build?.version);
        appendUpdateDetail(elements.server_update_details, t('targetPlatform'), overview?.build?.target);
        appendUpdateDetail(elements.server_update_details, t('sourceRepository'), overview?.repository);
        appendUpdateDetail(elements.server_update_details, t('updateState'), updateStatusMessage(status, overview?.operation_active));
        elements.server_update_security.replaceChildren();
        [t('signedManifestProtected'), t('confirmationProtected'), t('downgradeBlocked'), t('rollbackProtected')].forEach(value => {
          const item = document.createElement('span'); item.textContent = value; elements.server_update_security.append(item);
        });
        const unavailable = !overview || !overview.apply_available;
        elements.check_server_update.disabled = !overview || busy;
        elements.download_server_update.disabled = !overview || busy;
        elements.apply_server_update.disabled = unavailable || busy;
        elements.apply_server_update.title = unavailable ? t('updateUnavailable') : '';
        renderServerUpdateRelease(state.serverUpdateCheck);
      }

      async function checkServerUpdate() {
        setBusy(elements.check_server_update, true, 'saving');
        try {
          const response = await apiFetch('/api/v1/updates/server/check', { method: 'POST', headers: { Accept: 'application/json' }, timeoutMs: 45000, scope: 'update' });
          if (!response.ok) return showToast(await responseError(response), true);
          state.serverUpdateCheck = await response.json();
          renderUpdateCenter();
          showToast(t('updateChecked'));
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(elements.check_server_update, false); renderUpdateCenter(); }
      }

      function promptForUpdateConfirmation(messageKey, phrase) {
        const confirmation = window.prompt(`${t(messageKey)}\n\n${t('typeUpdateConfirmation', { phrase })}`, '');
        if (confirmation === null) return null;
        if (confirmation !== phrase) {
          showToast(t('updateConfirmationMismatch'), true);
          return null;
        }
        return confirmation;
      }

      async function downloadServerUpdate() {
        const confirmation = promptForUpdateConfirmation('confirmDownloadUpdate', 'DOWNLOAD');
        if (!confirmation) return;
        setBusy(elements.download_server_update, true, 'saving');
        try {
          const response = await apiFetch('/api/v1/updates/server/download', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ confirmation }), timeoutMs: 300000, scope: 'update' });
          if (!response.ok) return showToast(await responseError(response), true);
          const staged = await response.json();
          state.serverUpdateCheck = { ...(state.serverUpdateCheck || {}), latest_version: staged.version, asset_name: staged.archive_name, github_digest: staged.archive_sha256, signature_key_id: staged.signature_key_id, update_available: staged.version !== state.dashboard?.updateOverview?.build?.version };
          renderUpdateCenter();
          showToast(t('updateDownloaded'));
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(elements.download_server_update, false); renderUpdateCenter(); }
      }

      async function applyServerUpdate() {
        const confirmation = promptForUpdateConfirmation('confirmApplyUpdate', 'UPDATE');
        if (!confirmation) return;
        setBusy(elements.apply_server_update, true, 'saving');
        try {
          const response = await apiFetch('/api/v1/updates/server/apply', { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify({ confirmation }), timeoutMs: 300000, scope: 'update' });
          if (!response.ok) return showToast(await responseError(response), true);
          const scheduled = await response.json();
          if (state.dashboard?.updateOverview) {
            state.dashboard.updateOverview.status = { state: scheduled.state, operation: scheduled.operation, from_version: scheduled.from_version, to_version: scheduled.to_version, message: t('updateScheduled') };
            state.dashboard.updateOverview.operation_active = true;
          }
          renderUpdateCenter();
          showToast(t('updateScheduled'), false, 0);
        } catch (_) {
          if (state.dashboard?.updateOverview) {
            state.dashboard.updateOverview.status = { state: 'unknown', message: t('updateApplyResponseInterrupted') };
            state.dashboard.updateOverview.operation_active = true;
            renderUpdateCenter();
          }
          showToast(t('updateApplyResponseInterrupted'), true, 0);
        }
        finally { setBusy(elements.apply_server_update, false); renderUpdateCenter(); }
      }

      function renderAlerts() {
        const dashboard = state.dashboard;
        const channels = dashboard.alertChannels || {};
        elements.alert_channels.textContent = t('channelsConfigured', { webhook: t(channels.webhook_configured ? 'configured' : 'notConfigured'), smtp: t(channels.smtp_configured ? 'configured' : 'notConfigured') });
        elements.new_alert_rule.classList.toggle('hidden', state.identity.role === 'auditor');
        const events = dashboard.alertEvents || [];
        elements.alert_events.replaceChildren();
        if (!events.length) {
          const empty = document.createElement('div'); empty.className = 'empty-state'; empty.textContent = t('noAlertEvents'); elements.alert_events.append(empty);
        } else events.forEach(event => {
          const item = document.createElement('article');
          item.className = 'alert-item';
          item.style.borderLeftColor = event.severity === 'critical' ? 'var(--danger)' : event.severity === 'info' ? 'var(--accent)' : 'var(--warning)';
          const heading = document.createElement('strong'); heading.textContent = `${alertSeverityText(event.severity)} · ${event.rule_name}`;
          const detail = document.createElement('div'); detail.textContent = `${event.subject} · ${event.message} · ${formatTimestamp(event.updated_unix_seconds)}`;
          item.append(heading, detail); elements.alert_events.append(item);
        });
        const rules = dashboard.alertRules || [];
        elements.alert_rules.replaceChildren();
        if (!rules.length) {
          const row = document.createElement('tr'); const cell = document.createElement('td'); cell.colSpan = 8; cell.className = 'empty-state'; cell.textContent = t('noAlertRules'); row.append(cell); elements.alert_rules.append(row);
        }
        rules.forEach(rule => {
          const row = document.createElement('tr');
          const channels = [rule.notify_webhook ? 'Webhook' : '', rule.notify_email ? 'Email' : ''].filter(Boolean).join(' + ') || '—';
          const comparator = rule.comparator === 'less_or_equal' ? '≤' : '≥';
          [rule.name, alertMetricText(rule.metric), `${comparator} ${rule.threshold} · ${rule.evaluation_window_seconds}s`, rule.target || t('all'), alertSeverityText(rule.severity), channels, rule.enabled ? t('enabled') : t('disabled')].forEach(value => { const cell = document.createElement('td'); cell.textContent = value; row.append(cell); });
          const actions = document.createElement('td'); actions.className = 'table-actions';
          if (state.identity.role !== 'auditor') actions.append(actionButton(t('editPolicy'), () => openAlertRuleModal(rule)), actionButton(t('delete'), () => deleteAlertRule(rule), 'danger-button'));
          row.append(actions); elements.alert_rules.append(row);
        });
      }

      function auditCategory(event) {
        const action = event.action || '';
        if (action.startsWith('management.') || action.startsWith('server.update.')) return 'management';
        if (action.startsWith('client.')) return 'client';
        if (action.startsWith('p2p')) return 'p2p';
        if (action.startsWith('certificate.') || action.startsWith('acme.')) return 'certificate';
        return 'policy';
      }

      function auditActionText(event) {
        const action = event.action || '';
        const exact = {
          'management.login': 'auditLogin', 'management.login.failed': 'auditLoginFailed', 'management.password.changed': 'auditPasswordChanged', 'management.logout': 'auditLogout', 'client.enrolled': 'auditClientEnrolled', 'acme.config.updated': 'auditAcmeUpdated', 'p2p_node.registered': 'auditP2pUpdated', 'p2p.direct_connected': 'auditP2pDirect', 'p2p.relay_fallback': 'auditP2pRelay'
        };
        if (exact[action]) return t(exact[action]);
        if (action.includes('.policy.created')) return t('auditPolicyCreated');
        if (action.includes('.policy.updated')) return t('auditPolicyUpdated');
        if (action.includes('.policy.deleted')) return t('auditPolicyDeleted');
        if (action.endsWith('.registered')) return t('auditRegistered');
        if (action.startsWith('certificate.')) {
          if (action.endsWith('.started')) return t('auditCertificateStarted');
          if (action.endsWith('.succeeded')) return t('auditCertificateSucceeded');
          if (action.endsWith('.failed')) return t('auditCertificateFailed');
        }
        return action;
      }

      function auditKey(event) { return event.id != null ? String(event.id) : `${event.occurred_unix_seconds}|${event.action}|${event.subject}|${event.detail}`; }

      function renderAudit() {
        const events = state.dashboard.events || [];
        const query = state.auditSearch.trim().toLowerCase();
        const visible = events.filter(event => {
          if (state.auditCategory !== 'all' && auditCategory(event) !== state.auditCategory) return false;
          if (!query) return true;
          return [event.action, event.subject, event.detail, auditActionText(event)].join(' ').toLowerCase().includes(query);
        });
        elements.audit_count.textContent = t('auditCount', { visible: visible.length });
        elements.audit_list.replaceChildren();
        if (!visible.length) {
          const empty = document.createElement('div'); empty.className = 'empty-state'; empty.textContent = t('noActivity'); elements.audit_list.append(empty);
        }
        visible.forEach(event => {
          const key = auditKey(event);
          const item = document.createElement('article'); item.className = 'audit-item';
          const button = document.createElement('button'); button.type = 'button'; button.className = 'audit-summary'; button.setAttribute('aria-expanded', String(state.expandedAudit.has(key)));
          const time = document.createElement('span'); time.className = 'audit-time'; time.textContent = new Date(event.occurred_unix_seconds * 1000).toLocaleString(state.language === 'zh' ? 'zh-CN' : 'en', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
          const action = document.createElement('span'); action.className = 'audit-action'; action.textContent = auditActionText(event);
          const subject = document.createElement('span'); subject.className = 'audit-subject'; subject.textContent = event.subject || '—';
          const chevron = document.createElement('span'); chevron.className = 'audit-chevron'; chevron.textContent = '⌄';
          const detail = document.createElement('div'); detail.className = `audit-detail${state.expandedAudit.has(key) ? '' : ' hidden'}`;
          const dl = document.createElement('dl');
          [[t('action'), event.action], [t('subject'), event.subject || '—'], [t('detail'), event.detail || '—'], [t('occurredAt'), formatTimestamp(event.occurred_unix_seconds)]].forEach(([label, value]) => { const dt = document.createElement('dt'); const dd = document.createElement('dd'); dt.textContent = label; dd.textContent = value; dl.append(dt, dd); });
          detail.append(dl);
          button.append(time, action, subject, chevron);
          button.addEventListener('click', () => { const open = button.getAttribute('aria-expanded') !== 'true'; button.setAttribute('aria-expanded', String(open)); detail.classList.toggle('hidden', !open); if (open) state.expandedAudit.add(key); else state.expandedAudit.delete(key); });
          item.append(button, detail); elements.audit_list.append(item);
        });
        elements.audit_load_more.classList.toggle('hidden', state.auditLimit >= 100 || events.length < state.auditLimit);
      }

      function drawCharts() {
        if (!state.dashboard) return;
        if (state.route.view === 'overview') drawTrafficChart();
        if (state.route.view === 'metrics') renderMetrics();
        if (state.route.view === 'services' && state.route.service !== 'acme') {
          drawServiceTrendChart();
          drawServiceStatusChart();
        }
        if (state.route.view === 'clients') drawClientInsightCharts();
      }

      function scheduleResponsiveRender() {
        if (chartRenderFrame !== null) return;
        chartRenderFrame = requestAnimationFrame(() => {
          chartRenderFrame = null;
          if (!elements.appearance_popover.classList.contains('hidden')) {
            positionPopover(elements.appearance_popover, elements.appearance_button);
          }
          drawCharts();
        });
      }

      function setupChartResizeObserver() {
        if (!('ResizeObserver' in window)) return;
        chartResizeObserver?.disconnect();
        chartResizeObserver = new ResizeObserver(entries => {
          let changed = false;
          entries.forEach(entry => {
            const width = Math.round(entry.contentRect.width * 2) / 2;
            const height = Math.round(entry.contentRect.height * 2) / 2;
            const previous = observedChartSizes.get(entry.target);
            if (!previous || previous.width !== width || previous.height !== height) {
              observedChartSizes.set(entry.target, { width, height });
              changed = true;
            }
          });
          if (changed) scheduleResponsiveRender();
        });
        document.querySelectorAll('.chart-wrap').forEach(container => chartResizeObserver.observe(container));
        chartResizeObserver.observe(elements.workspace);
      }

      function setupPixelRatioObserver() {
        const ratio = window.devicePixelRatio || 1;
        const query = matchMedia(`(resolution: ${ratio}dppx)`);
        const refresh = () => {
          if (pixelRatioMedia?.removeEventListener) pixelRatioMedia.removeEventListener('change', refresh);
          else if (pixelRatioMedia?.removeListener) pixelRatioMedia.removeListener(refresh);
          pixelRatioMedia = null;
          setupPixelRatioObserver();
          scheduleResponsiveRender();
        };
        pixelRatioMedia = query;
        if (query.addEventListener) query.addEventListener('change', refresh, { once: true });
        else if (query.addListener) query.addListener(refresh);
      }

      function policyInitialValues(type, policy = null) {
        const schema = POLICY_TYPES[type];
        const values = {};
        schema.fields.forEach(field => { values[field.name] = policy?.[field.name] ?? field.default ?? (field.type === 'checkbox' ? false : ''); });
        if (type === 'http') {
          values.tls_mode = policy?.tls?.mode || 'disabled';
          values.redirect_http_to_https = Boolean(policy?.tls?.redirect_http_to_https);
        }
        return values;
      }

      function fieldLabel(field) {
        const suffix = !field.required && field.type !== 'checkbox' ? ` · ${t('optional')}` : '';
        const protocol = field.portProtocol || (field.portProtocolField ? (state.drawer.values?.[field.portProtocolField] || 'tcp') : null);
        const portHint = protocol ? ` · ${portPolicyDescription(protocol)}` : '';
        return `${t(field.label)}${suffix}${portHint}`;
      }

      function allowedPortExpression(protocol = null) {
        const policy = state.dashboard?.publicPortPolicy;
        if (!policy) return '32000-32999';
        const selected = protocol || (state.drawer.type === 'udp' ? 'udp' : state.drawer.type === 'ports' ? (state.drawer.values?.protocol || 'tcp') : 'tcp');
        return selected === 'udp' ? policy.udp_allowed : policy.tcp_allowed;
      }

      function portPolicyDescription(protocol = null) {
        const selected = protocol || (state.drawer.type === 'udp' ? 'udp' : state.drawer.type === 'ports' ? (state.drawer.values?.protocol || 'tcp') : 'tcp');
        const policy = state.dashboard?.publicPortPolicy;
        const allowed = allowedPortExpression(selected);
        const reserved = policy ? (selected === 'udp' ? policy.udp_reserved : policy.tcp_reserved) : '';
        return `${t('allowedPorts', { ports: allowed })}${reserved ? `; ${t('reservedPorts', { ports: reserved })}` : ''}`;
      }

      function appendClientOptions(select, optional = false) {
        const clients = state.dashboard?.clients || [];
        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = optional ? t('anyAuthenticatedClient') : clients.length ? t('selectClient') : t('noClients');
        placeholder.disabled = !optional;
        placeholder.selected = true;
        select.append(placeholder);
        clients.filter(client => client.enabled !== false).forEach(client => {
          const option = document.createElement('option');
          option.value = client.client_id;
          const configMode = client.config_mode || 'local';
          const configStatus = client.config_sync_status || 'unknown';
          option.textContent = `${client.name} · ${client.platform} · ${configMode}/${configStatus}`;
          option.title = client.config_sync_error || '';
          select.append(option);
        });
      }

      function createDrawerField(field, value) {
        const label = document.createElement('label');
        label.classList.toggle('full', Boolean(field.full));
        label.dataset.fieldName = field.name;
        if (field.when) {
          label.dataset.whenField = field.when.field;
          label.dataset.whenValue = field.when.value;
        }
        let input;
        if (field.type === 'client' || field.type === 'optionalClient') {
          input = document.createElement('select');
          appendClientOptions(input, field.type === 'optionalClient');
        } else if (field.type === 'select') {
          input = document.createElement('select');
          field.options.forEach(optionData => {
            const option = document.createElement('option');
            option.value = optionData.value;
            option.textContent = optionData.labelKey ? t(optionData.labelKey) : optionData.label;
            input.append(option);
          });
        } else {
          input = document.createElement('input');
          input.type = field.type === 'checkbox' ? 'checkbox' : field.type;
        }
        input.name = field.name;
        if (field.required) input.required = true;
        if (field.min != null) input.min = String(field.min);
        if (field.max != null) input.max = String(field.max);
        if (field.type === 'checkbox') {
          label.classList.add('check-label');
          input.checked = Boolean(value);
          const span = document.createElement('span'); span.textContent = fieldLabel(field); label.append(input, span);
        } else {
          input.value = value ?? '';
          const span = document.createElement('span'); span.textContent = fieldLabel(field); label.append(span, input);
        }
        return label;
      }

      function renderDrawerFields(values = state.drawer.values) {
        const schema = POLICY_TYPES[state.drawer.type];
        elements.policy_fields.replaceChildren(...schema.fields.map(field => createDrawerField(field, values?.[field.name])));
        updateDrawerConditions();
      }

      function updateDrawerConditions() {
        elements.policy_fields.querySelectorAll('[data-when-field]').forEach(wrapper => {
          const controller = elements.policy_form.elements[wrapper.dataset.whenField];
          const visible = controller && controller.value === wrapper.dataset.whenValue;
          wrapper.classList.toggle('hidden', !visible);
          const input = wrapper.querySelector('input,select,textarea');
          if (input) input.disabled = !visible;
        });
      }

      function updateDrawerPortLabels() {
        if (!state.drawer.open) return;
        POLICY_TYPES[state.drawer.type].fields.filter(field => field.portProtocol || field.portProtocolField).forEach(field => {
          const span = elements.policy_fields.querySelector(`[data-field-name="${field.name}"] > span`);
          if (span) span.textContent = fieldLabel(field);
        });
      }

      function collectDrawerValues() {
        if (!state.drawer.open) return {};
        const values = {};
        POLICY_TYPES[state.drawer.type].fields.forEach(field => {
          const input = elements.policy_form.elements[field.name];
          if (!input) return;
          values[field.name] = field.type === 'checkbox' ? input.checked : input.value;
        });
        return values;
      }

      function refreshDrawerLanguage() {
        const values = collectDrawerValues();
        const schema = POLICY_TYPES[state.drawer.type];
        elements.drawer_title.textContent = t(state.drawer.id ? schema.editKey : schema.createKey);
        elements.drawer_subtitle.textContent = t(schema.subtitleKey);
        elements.drawer_cancel.textContent = t('cancel');
        elements.drawer_submit.textContent = t('save');
        renderDrawerFields(values);
      }

      function openPolicyDrawer(type, policy = null) {
        if (!POLICY_TYPES[type]) return;
        state.drawer = { open: true, type, id: policy?.id || null, dirty: false, values: policyInitialValues(type, policy) };
        const schema = POLICY_TYPES[type];
        elements.drawer_title.textContent = t(policy ? schema.editKey : schema.createKey);
        elements.drawer_subtitle.textContent = t(schema.subtitleKey);
        renderDrawerFields(state.drawer.values);
        elements.drawer_backdrop.classList.remove('hidden');
        elements.policy_drawer.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        requestAnimationFrame(() => elements.policy_fields.querySelector('input:not([type="checkbox"]),select')?.focus());
      }

      function beginPolicyEdit(type, policy) { openPolicyDrawer(type, policy); }

      function duplicatePolicy(type, policy) {
        if (!POLICY_TYPES[type]) return;
        const values = policyInitialValues(type, policy);
        values.name = `${values.name || type}-copy`;
        state.drawer = { open: true, type, id: null, dirty: true, values };
        const schema = POLICY_TYPES[type];
        elements.drawer_title.textContent = t(schema.createKey);
        elements.drawer_subtitle.textContent = t(schema.subtitleKey);
        renderDrawerFields(values);
        elements.drawer_backdrop.classList.remove('hidden');
        elements.policy_drawer.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        requestAnimationFrame(() => elements.policy_form.elements.name?.focus());
      }

      function cancelEdit(force = false) {
        if (!state.drawer.open) return;
        if (!force && state.drawer.dirty && !window.confirm(t('cancel') + '?')) return;
        state.drawer = { open: false, type: null, id: null, dirty: false, values: null };
        elements.drawer_backdrop.classList.add('hidden');
        elements.policy_drawer.classList.add('hidden');
        elements.policy_form.reset();
        document.body.style.overflow = '';
        elements.new_policy?.focus();
      }

      function normalizePolicyPayload(type, values) {
        const payload = { ...values };
        POLICY_TYPES[type].fields.forEach(field => {
          if (field.type === 'number') payload[field.name] = values[field.name] === '' ? null : Number(values[field.name]);
          if (field.type === 'checkbox') payload[field.name] = Boolean(values[field.name]);
        });
        if ('bandwidth_limit_bps' in payload && !payload.bandwidth_limit_bps) payload.bandwidth_limit_bps = null;
        if (type === 'ports') {
          if (payload.protocol === 'tcp') { payload.max_sessions = null; payload.session_idle_timeout_seconds = null; }
          else payload.max_connections = null;
        }
        if (type === 'secret' && !payload.allowed_client_id) payload.allowed_client_id = null;
        if (type === 'http') {
          delete payload.tls_mode;
          delete payload.redirect_http_to_https;
        }
        return payload;
      }

      async function savePolicy(formElement, resource, payload, fallbackKey = 'requestFailed') {
        const editingId = state.drawer.id || '';
        const response = await apiFetch(`/api/v1/${resource}${editingId ? `/${editingId}` : ''}`, {
          method: editingId ? 'PUT' : 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (response.status === 401) return { ok: false, editing: Boolean(editingId), data: null };
        if (!response.ok) { showToast(await responseError(response, fallbackKey), true); return { ok: false, editing: Boolean(editingId), data: null }; }
        let data = null;
        try { data = await response.json(); } catch (_) {}
        return { ok: true, editing: Boolean(editingId), data };
      }

      async function submitPolicy(event) {
        event.preventDefault();
        const type = state.drawer.type;
        const schema = POLICY_TYPES[type];
        if (!schema || !elements.policy_form.reportValidity()) return;
        const submit = elements.drawer_submit;
        setBusy(submit, true);
        const values = collectDrawerValues();
        const editingId = state.drawer.id;
        try {
          const result = await savePolicy(elements.policy_form, schema.resource, normalizePolicyPayload(type, values), 'requestFailed');
          if (!result.ok) return;
          const policyId = editingId || result.data?.id;
          if (type === 'http') {
            if (!result.editing && policyId) {
              state.drawer.id = policyId;
              state.drawer.values = values;
              elements.drawer_title.textContent = t(schema.editKey);
            }
            const tlsResponse = await apiFetch(`/api/v1/http-routes/${policyId}/tls`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: values.tls_mode, redirect_http_to_https: values.tls_mode === 'acme' && Boolean(values.redirect_http_to_https) }) });
            if (tlsResponse.status === 401) return;
            if (!tlsResponse.ok) {
              const detail = await responseError(tlsResponse, 'errorAcme');
              showToast(result.editing ? detail : `${t('routeCreatedTlsFailed')} ${detail}`, true, 0);
              state.drawer.dirty = true;
              await loadManagementData({ forceHistory: false });
              return;
            }
          }
          if (!result.editing && type === 'secret' && result.data?.access_key) showToast(t('secretCreated', { key: result.data.access_key }), false, 0);
          else if (!result.editing && type === 'socks5' && result.data?.password) showToast(t('socks5Created', { username: result.data.username, password: result.data.password }), false, 0);
          else if (!result.editing && type === 'http-proxy' && result.data?.password) showToast(t('httpProxyCreated', { username: result.data.username, password: result.data.password }), false, 0);
          else showToast(t(result.editing ? 'policyUpdated' : 'policyCreated'));
          cancelEdit(true);
          await loadManagementData({ forceHistory: false });
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function setPolicyEnabled(type, policy) {
        const schema = POLICY_TYPES[type];
        const response = await apiFetch(`/api/v1/${schema.resource}/${policy.id}/enabled`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !policy.enabled }) });
        if (response.status === 401) return;
        if (!response.ok) return showToast(await responseError(response), true);
        showToast(t(policy.enabled ? 'policyDisabled' : 'policyEnabled'));
        await loadManagementData({ forceHistory: false });
      }

      async function deletePolicy(type, policy) {
        if (!window.confirm(t('confirmDelete'))) return;
        const schema = POLICY_TYPES[type];
        const response = await apiFetch(`/api/v1/${schema.resource}/${policy.id}`, { method: 'DELETE' });
        if (response.status === 401) return;
        if (!response.ok) return showToast(await responseError(response), true);
        showToast(t('policyDeleted'));
        await loadManagementData({ forceHistory: false });
      }

      async function updateRouteTls(id, mode, redirect) {
        const response = await apiFetch(`/api/v1/http-routes/${id}/tls`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode, redirect_http_to_https: redirect }) });
        if (response.status === 401) return;
        if (!response.ok) return showToast(await responseError(response, 'errorAcme'), true);
        showToast(t('tlsUpdated'));
        await loadManagementData({ forceHistory: false });
      }

      async function runCertificateAction(id, action) {
        const response = await apiFetch(`/api/v1/http-routes/${id}/certificate/${action}`, { method: 'POST' });
        if (response.status === 401) return;
        if (!response.ok) return showToast(await responseError(response, 'errorAcme'), true);
        showToast(t('certificateQueued'));
        await loadManagementData({ forceHistory: false });
      }

      async function saveAcme(event) {
        event.preventDefault();
        const form = event.currentTarget;
        const submit = event.submitter;
        setBusy(submit, true);
        try {
          const response = await apiFetch('/api/v1/acme/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: form.elements.enabled.checked, environment: form.elements.environment.value, directory_url: form.elements.directory_url.value, contact_email: form.elements.contact_email.value, terms_accepted: form.elements.terms_accepted.checked, renew_before_days: Number(form.elements.renew_before_days.value) }) });
          if (response.status === 401) return;
          if (!response.ok) return showToast(await responseError(response, 'errorAcme'), true);
          delete form.dataset.dirty;
          showToast(t('acmeSaved'));
          await loadManagementData({ forceHistory: false });
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      function showLogin(messageKey = '') {
        state.identity = null;
        elements.utility_session.classList.add('hidden');
        elements.account_shell.classList.add('hidden');
        elements.global_search_shell.classList.add('hidden');
        elements.workspace.classList.add('hidden');
        elements.login_shell.classList.remove('hidden');
        elements.login.classList.remove('hidden');
        elements.login_totp_label.classList.add('hidden');
        elements.login_totp.value = '';
        elements.initial_password_form.classList.add('hidden');
        if (messageKey) showToast(t(messageKey), messageKey !== 'signedOut');
      }

      function showInitialPassword(identity) {
        state.identity = identity;
        elements.utility_session.classList.add('hidden');
        elements.account_shell.classList.add('hidden');
        elements.global_search_shell.classList.add('hidden');
        elements.workspace.classList.add('hidden');
        elements.login_shell.classList.remove('hidden');
        elements.login.classList.add('hidden');
        elements.initial_password_form.classList.remove('hidden');
        showToast(t('changeRequired'));
        requestAnimationFrame(() => elements.initial_new_password.focus());
      }

      function showWorkspace(identity) {
        state.identity = identity;
        elements.utility_session.classList.remove('hidden');
        elements.account_shell.classList.remove('hidden');
        elements.global_search_shell.classList.remove('hidden');
        elements.login_shell.classList.add('hidden');
        elements.workspace.classList.remove('hidden');
        elements.login.classList.remove('hidden');
        elements.initial_password_form.classList.add('hidden');
        updateIdentityUi();
        if (!location.hash || location.hash === '#/') location.hash = '#/overview';
        renderRoute();
      }

      function resetForExpiredSession(messageKey = 'sessionExpired') {
        state.sessionGeneration += 1;
        state.routeGeneration += 1;
        abortActiveRequests();
        if (state.refreshTimer) clearInterval(state.refreshTimer);
        state.refreshTimer = null;
        state.loading = false;
        state.pendingLoad = false;
        state.pendingForceHistory = false;
        state.loadPromise = null;
        state.dashboard = null;
        state.trafficHistory = [];
        state.serviceTrafficHistory = [];
        state.historyMeta = null;
        state.serviceHistoryMeta = null;
        state.historyCache.clear();
        state.historyRequestGeneration += 1;
        state.historyActiveKey = null;
        state.historyPromise = null;
        cancelEdit(true);
        togglePopover(elements.account_menu, elements.account_button, false);
        showLogin(messageKey);
      }

      async function loadIdentity() {
        const generation = state.sessionGeneration;
        try {
          const response = await apiFetch('/api/v1/auth/me', { headers: { Accept: 'application/json' }, skipAuthReset: true, scope: 'identity' });
          if (generation !== state.sessionGeneration) return;
          if (response.status === 401) return showLogin();
          if (!response.ok) return showLogin();
          const identity = await response.json();
          if (generation !== state.sessionGeneration) return;
          if (identity.password_change_required) return showInitialPassword(identity);
          showWorkspace(identity);
          await loadManagementData({ forceHistory: true });
          startAutoRefresh();
        } catch (_) { if (generation === state.sessionGeneration) showLogin(); }
      }

      async function login(event) {
        event.preventDefault();
        state.sessionGeneration += 1;
        abortActiveRequests('identity');
        const generation = state.sessionGeneration;
        const submit = event.submitter;
        setBusy(submit, true, 'signingIn');
        try {
          const response = await apiFetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: elements.username.value, password: elements.password.value, totp_code: elements.login_totp_label.classList.contains('hidden') ? null : elements.login_totp.value }), skipAuthReset: true });
          if (generation !== state.sessionGeneration) return;
          if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            if (error.code === 'totp_required') {
              elements.login_totp_label.classList.remove('hidden');
              elements.login_totp.required = true;
              showToast(t('totpRequired'));
              requestAnimationFrame(() => elements.login_totp.focus());
              return;
            }
            elements.password.value = '';
            elements.login_totp.value = '';
            return showToast(error.code === 'invalid_totp_code' ? t('invalidTotp') : t('signInFailed'), true);
          }
          const identity = await response.json();
          elements.login.reset();
          elements.login_totp_label.classList.add('hidden');
          elements.login_totp.required = false;
          if (generation !== state.sessionGeneration) return;
          if (identity.password_change_required) return showInitialPassword(identity);
          showWorkspace(identity);
          await loadManagementData({ forceHistory: true });
          startAutoRefresh();
        } catch (_) { showToast(t('requestFailed'), true); }
        finally { setBusy(submit, false); }
      }

      async function changePassword(newPassword, submit) {
        setBusy(submit, true, 'changingPassword');
        try {
          const response = await apiFetch('/api/v1/auth/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ new_password: newPassword }) });
          if (response.status === 401) return false;
          if (!response.ok) return showToast(t('passwordChangeFailed'), true);
          showToast(t('passwordChanged'));
          return true;
        } catch (_) { showToast(t('requestFailed'), true); return false; }
        finally { setBusy(submit, false); }
      }

      async function submitInitialPassword(event) {
        event.preventDefault();
        if (elements.initial_new_password.value !== elements.initial_confirm_password.value) return showToast(t('passwordsMismatch'), true);
        const changed = await changePassword(elements.initial_new_password.value, event.submitter);
        if (!changed) return;
        elements.initial_password_form.reset();
        const response = await apiFetch('/api/v1/auth/me');
        if (!response.ok) return resetForExpiredSession();
        const identity = await response.json();
        showWorkspace(identity);
        await loadManagementData({ forceHistory: true });
        startAutoRefresh();
      }

      async function submitAccountPassword(event) {
        event.preventDefault();
        if (elements.account_new_password.value !== elements.account_confirm_password.value) return showToast(t('passwordsMismatch'), true);
        const changed = await changePassword(elements.account_new_password.value, event.submitter);
        if (!changed) return;
        elements.password_form.reset();
        togglePasswordModal(false);
      }

      function togglePasswordModal(show) {
        elements.password_modal.classList.toggle('hidden', !show);
        if (show) requestAnimationFrame(() => elements.account_new_password.focus());
      }

      function historyQuery(range = state.trendRange, protocol = 'total') {
        const steps = { '1h': 15, '12h': 150, '1d': 300, '7d': 2100, '30d': 9000 };
        return `/api/v1/metrics/history?range=${encodeURIComponent(range)}&step=${steps[range] || 15}&protocol=${encodeURIComponent(protocol)}`;
      }

      function historyCacheKey(range, protocol) { return `${protocol}:${range}`; }

      function serviceHistoryProtocol(type = state.route.service) {
        if (type === 'tcp') return 'tcp';
        if (type === 'udp') return 'udp';
        if (type === 'http' || type === 'sni') return 'web';
        if (type === 'socks5' || type === 'http-proxy') return 'proxy';
        if (type === 'secret') return 'secret';
        if (type === 'ports') {
          const protocols = new Set((state.dashboard?.portGroups || []).map(policy => policy.protocol).filter(Boolean));
          return protocols.size === 1 ? [...protocols][0] : 'total';
        }
        return 'total';
      }

      function setHistoryLoading(target, loading) {
        const canvas = target === 'service' ? elements.service_trend_chart : elements.traffic_chart;
        const panel = canvas?.closest('.chart-panel');
        if (!panel) return;
        panel.dataset.loadingLabel = t('loadingHistory');
        panel.classList.toggle('is-loading', loading);
      }

      function applyHistoryPayload(target, range, protocol, payload) {
        if (target === 'service') {
          if (state.route.view !== 'services' || state.route.service === 'acme' || state.serviceTrendRange !== range || serviceHistoryProtocol() !== protocol) return;
          state.serviceHistoryProtocol = protocol;
          state.serviceTrafficHistory = Array.isArray(payload.points) ? payload.points : [];
          state.serviceHistoryMeta = payload;
          drawServiceTrendChart();
          return;
        }
        if (state.route.view !== 'overview' || state.trendRange !== range || protocol !== 'total') return;
        state.trafficHistory = Array.isArray(payload.points) ? payload.points : [];
        state.historyMeta = payload;
        drawTrafficChart();
      }

      function loadHistory(range, protocol, { force = false, target = 'overview' } = {}) {
        const key = historyCacheKey(range, protocol);
        const cached = state.historyCache.get(key);
        const cacheFresh = cached && Date.now() - cached.fetchedAt < 45000;
        if (cached) applyHistoryPayload(target, range, protocol, cached.payload);
        if (!force && cacheFresh) return Promise.resolve(cached.payload);
        if (!force && state.historyActiveKey === key && state.historyPromise) return state.historyPromise;
        state.historyRequestGeneration += 1;
        const generation = state.historyRequestGeneration;
        abortActiveRequests('history');
        setHistoryLoading(target, true);
        const request = (async () => {
          try {
            const response = await apiFetch(historyQuery(range, protocol), { headers: { Accept: 'application/json' }, scope: 'history' });
            if (generation !== state.historyRequestGeneration || response.status === 401) return null;
            if (!response.ok) return null;
            const payload = await response.json();
            if (generation !== state.historyRequestGeneration) return null;
            state.historyCache.set(key, { payload, fetchedAt: Date.now() });
            if (state.historyCache.size > 30) state.historyCache.delete(state.historyCache.keys().next().value);
            applyHistoryPayload(target, range, protocol, payload);
            return payload;
          } catch (error) {
            if (error?.name !== 'AbortError' && generation === state.historyRequestGeneration && !cached) showToast(t('statusFailed'), true);
            return null;
          } finally {
            if (generation === state.historyRequestGeneration) {
              setHistoryLoading(target, false);
              state.historyActiveKey = null;
              state.historyPromise = null;
            }
          }
        })();
        state.historyActiveKey = key;
        state.historyPromise = request;
        return request;
      }

      function loadRouteHistory({ force = false } = {}) {
        if (!state.identity || !state.dashboard) return Promise.resolve(null);
        if (state.route.view === 'overview') return loadHistory(state.trendRange, 'total', { force, target: 'overview' });
        if (state.route.view === 'services' && state.route.service !== 'acme') {
          const protocol = serviceHistoryProtocol();
          state.serviceHistoryProtocol = protocol;
          return loadHistory(state.serviceTrendRange, protocol, { force, target: 'service' });
        }
        return Promise.resolve(null);
      }

      function captureFallbackHistory(metrics, status) {
        const now = Date.now() / 1000;
        const totals = aggregateTraffic();
        const activeConnections = metrics.tcp_active_connections + metrics.http_active_connections + metrics.https_active_connections + metrics.sni_active_connections + metrics.socks5_active_connections + metrics.http_proxy_active_connections;
        const activeSessions = metrics.udp_active_sessions + metrics.socks5_udp_active_associations;
        if (state.lastTrafficTotals && state.lastTrafficTotals.instance === status.instance_id && totals.inbound >= state.lastTrafficTotals.inbound && totals.outbound >= state.lastTrafficTotals.outbound) {
          const elapsed = Math.max(1, now - state.lastTrafficTotals.timestamp);
          state.trafficHistory.push({ timestamp_unix_seconds: now, inbound_bps: (totals.inbound - state.lastTrafficTotals.inbound) / elapsed, outbound_bps: (totals.outbound - state.lastTrafficTotals.outbound) / elapsed, active_connections: activeConnections, active_sessions: activeSessions, requests_per_second: 0, errors_per_second: 0 });
          state.trafficHistory = state.trafficHistory.slice(-720);
        }
        state.lastTrafficTotals = { ...totals, timestamp: now, instance: status.instance_id };
      }

      function emptyDashboard() {
        const metrics = new Proxy({}, { get(target, key) { return key in target ? target[key] : 0; } });
        return { status: {}, metrics, events: [], users: [], sessions: [], apiTokens: [], updateOverview: null, fleetOverview: { peers: [], conflicts: [], failover_order: [] }, alertRules: [], alertEvents: [], alertChannels: {}, tcpPolicies: [], udpPolicies: [], portGroups: [], httpRoutes: [], sniRoutes: [], secretPolicies: [], socks5Policies: [], httpProxyPolicies: [], clients: [], p2pNodes: [], publicPortPolicy: { tcp_allowed: '32000-32999', udp_allowed: '32000-32999', tcp_reserved: '', udp_reserved: '' }, acme: { enabled: false, environment: 'staging', directory_url: acmeDirectories.staging, contact_email: '', terms_accepted: false, renew_before_days: 30, account_registered: false } };
      }

      function managementRequestPlan({ includeHistory = false } = {}) {
        const common = [{ key: 'status', url: '/api/v1/status' }, { key: 'publicPortPolicy', url: '/api/v1/public-port-policy' }];
        if (state.route.view === 'overview') {
          const plan = [...common,
            { key: 'metrics', url: '/api/v1/metrics' }, { key: 'tcpPolicies', url: '/api/v1/tcp-tunnels' }, { key: 'udpPolicies', url: '/api/v1/udp-tunnels' }, { key: 'portGroups', url: '/api/v1/port-groups' }, { key: 'httpRoutes', url: '/api/v1/http-routes' }, { key: 'sniRoutes', url: '/api/v1/sni-routes' }, { key: 'secretPolicies', url: '/api/v1/secret-tunnels' }, { key: 'socks5Policies', url: '/api/v1/socks5-proxies' }, { key: 'httpProxyPolicies', url: '/api/v1/http-proxies' }, { key: 'clients', url: '/api/v1/clients' }, { key: 'alertEvents', url: '/api/v1/alerts/events?active=true&limit=100', optional: true }
          ];
          return includeHistory ? [...plan, { key: 'history', url: historyQuery(), optional: true }] : plan;
        }
        if (state.route.view === 'metrics') return [...common, { key: 'metrics', url: '/api/v1/metrics' }];
        if (state.route.view === 'p2p') return [...common, { key: 'clients', url: '/api/v1/clients' }, { key: 'p2pNodes', url: '/api/v1/p2p/nodes' }];
        if (state.route.view === 'fleet') return [...common, { key: 'fleetOverview', url: '/api/v1/fleet/overview' }];
        if (state.route.view === 'clients') return [...common, { key: 'clients', url: '/api/v1/clients' }];
        if (state.route.view === 'users') return [...common, { key: 'users', url: '/api/v1/users' }];
        if (state.route.view === 'sessions') return [...common, { key: 'sessions', url: '/api/v1/sessions' }, { key: 'apiTokens', url: '/api/v1/api-tokens' }];
        if (state.route.view === 'updates') return [...common, { key: 'updateOverview', url: '/api/v1/updates/server' }];
        if (state.route.view === 'alerts') return [...common, { key: 'alertRules', url: '/api/v1/alerts/rules' }, { key: 'alertEvents', url: '/api/v1/alerts/events?active=true&limit=100' }, { key: 'alertChannels', url: '/api/v1/alerts/channels' }];
        if (state.route.view === 'activity') return [...common, { key: 'events', url: `/api/v1/audit?limit=${Math.min(100, state.auditLimit)}` }];
        if (state.route.service === 'acme') return [...common, { key: 'acme', url: '/api/v1/acme/config' }];
        const schema = POLICY_TYPES[state.route.service] || POLICY_TYPES.tcp;
        return [...common, { key: 'clients', url: '/api/v1/clients' }, { key: schema.dataKey, url: `/api/v1/${schema.resource}` }];
      }

      async function loadManagementData({ forceHistory = false } = {}) {
        if (!state.identity) return;
        if (state.loading && state.loadPromise) {
          state.pendingLoad = true;
          state.pendingForceHistory ||= forceHistory;
          return state.loadPromise;
        }
        const generation = state.sessionGeneration;
        const routeGeneration = state.routeGeneration;
        state.loading = true;
        state.loadPromise = (async () => {
          const plan = managementRequestPlan({ includeHistory: false });
          let responses;
          try { responses = await Promise.all(plan.map(item => apiFetch(item.url, { headers: { Accept: 'application/json' }, scope: 'management' }))); }
          catch (_) { if (generation === state.sessionGeneration && routeGeneration === state.routeGeneration) showToast(t('statusFailed'), true); return; }
          if (generation !== state.sessionGeneration || routeGeneration !== state.routeGeneration) return;
          if (responses.some(response => response.status === 401)) return;
          if (responses.some((response, index) => !response.ok && !plan[index].optional)) { showToast(t('statusFailed'), true); return; }
          const parsed = await Promise.all(responses.map(async (response, index) => response.ok ? [plan[index].key, await response.json()] : [plan[index].key, null]));
          if (generation !== state.sessionGeneration || routeGeneration !== state.routeGeneration) return;
          state.dashboard ||= emptyDashboard();
          parsed.forEach(([key, value]) => {
            if (value == null) return;
            if (key === 'history') {
              state.trafficHistory = Array.isArray(value.points) ? value.points : [];
              state.historyMeta = value;
            } else if (key === 'metrics') state.dashboard.metrics = new Proxy(value, { get(target, property) { return property in target ? target[property] : 0; } });
            else state.dashboard[key] = value;
          });
          if (!state.trafficHistory.length && parsed.some(([key]) => key === 'metrics')) captureFallbackHistory(state.dashboard.metrics, state.dashboard.status);
          elements.last_refresh.textContent = `${t('refreshed')}: ${new Date().toLocaleTimeString(state.language === 'zh' ? 'zh-CN' : 'en')}`;
          renderRoute();
          loadRouteHistory({ force: forceHistory }).catch(() => {});
        })().finally(() => {
          if (generation === state.sessionGeneration && routeGeneration === state.routeGeneration) {
            state.loading = false;
            state.loadPromise = null;
            if (state.pendingLoad) {
              state.pendingLoad = false;
              const pendingForceHistory = state.pendingForceHistory;
              state.pendingForceHistory = false;
              queueMicrotask(() => loadManagementData({ forceHistory: pendingForceHistory }));
            }
          }
        });
        return state.loadPromise;
      }

      function startAutoRefresh() {
        if (state.refreshTimer) clearInterval(state.refreshTimer);
        state.refreshTimer = setInterval(() => {
          if (!document.hidden) loadManagementData({ forceHistory: false }).catch(() => {});
        }, 5000);
      }

      async function logout() {
        abortActiveRequests();
        try { await apiFetch('/api/v1/auth/logout', { method: 'POST', skipAuthReset: true }); }
        finally { resetForExpiredSession('signedOut'); }
      }

      function setLanguage(language) {
        state.language = language;
        safeStorageSet('linklake-language', language);
        applyLanguage();
      }

      async function performGlobalSearch() {
        const query = elements.global_search.value.trim();
        if (query.length < 2) {
          elements.global_search_results.classList.add('hidden');
          elements.global_search_results.replaceChildren();
          return;
        }
        const response = await apiFetch(`/api/v1/search?q=${encodeURIComponent(query)}`, { headers: { Accept: 'application/json' }, scope: 'search' });
        if (!response.ok) return;
        const results = await response.json();
        elements.global_search_results.replaceChildren();
        if (!results.length) {
          const empty = document.createElement('div'); empty.className = 'empty-state'; empty.style.padding = '16px'; empty.textContent = t('noSearchResults'); elements.global_search_results.append(empty);
        } else results.forEach(result => {
          const button = document.createElement('button'); button.type = 'button';
          const title = document.createElement('strong'); title.textContent = `${result.kind.toUpperCase()} · ${result.title}`;
          const detail = document.createElement('small'); detail.textContent = `${result.subtitle} · ${result.id}`;
          button.append(title, detail);
          button.addEventListener('click', () => {
            location.hash = result.href.replace(/^#/, '');
            elements.global_search_results.classList.add('hidden');
            elements.global_search.value = '';
          });
          elements.global_search_results.append(button);
        });
        elements.global_search_results.classList.remove('hidden');
      }

      function setupTrafficTooltip() {
        const update = event => {
          if (!state.trafficHistory.length) return;
          const rect = elements.traffic_chart.getBoundingClientRect();
          const clientX = event.touches?.[0]?.clientX ?? event.clientX;
          const fraction = Math.max(0, Math.min(1, (clientX - rect.left - 48) / Math.max(1, rect.width - 62)));
          const start = Number(state.trafficHistory[0].timestamp_unix_seconds);
          const end = Number(state.trafficHistory.at(-1).timestamp_unix_seconds);
          const target = start + (end - start) * fraction;
          const point = state.trafficHistory.reduce((best, current) => Math.abs(Number(current.timestamp_unix_seconds) - target) < Math.abs(Number(best.timestamp_unix_seconds) - target) ? current : best, state.trafficHistory[0]);
          elements.traffic_tooltip.innerHTML = `<strong>${new Date(point.timestamp_unix_seconds * 1000).toLocaleString(state.language === 'zh' ? 'zh-CN' : 'en')}</strong><br>${t('inbound')}: ${formatRate(point.inbound_bps)}<br>${t('outbound')}: ${formatRate(point.outbound_bps)}<br>${t('activeSessions')}: ${Number(point.active_connections || 0) + Number(point.active_sessions || 0)}`;
          elements.traffic_tooltip.classList.remove('hidden');
          const left = Math.max(8, Math.min(rect.width - 150, clientX - rect.left + 10));
          elements.traffic_tooltip.style.left = `${left}px`;
          elements.traffic_tooltip.style.top = '36px';
        };
        elements.traffic_chart.addEventListener('mousemove', update);
        elements.traffic_chart.addEventListener('touchstart', update, { passive: true });
        elements.traffic_chart.addEventListener('touchmove', update, { passive: true });
        elements.traffic_chart.addEventListener('mouseleave', () => elements.traffic_tooltip.classList.add('hidden'));
      }

      function bindEvents() {
        elements.appearance_button.addEventListener('click', event => { event.stopPropagation(); togglePopover(elements.appearance_popover, elements.appearance_button); });
        document.querySelectorAll('[data-theme-choice]').forEach(button => button.addEventListener('click', () => applyTheme(button.dataset.themeChoice, document.documentElement.dataset.palette)));
        document.querySelectorAll('[data-palette-choice]').forEach(button => button.addEventListener('click', () => applyTheme(document.documentElement.dataset.themeMode, button.dataset.paletteChoice)));
        systemTheme.addEventListener('change', () => { if (document.documentElement.dataset.themeMode === 'system') applyTheme('system', document.documentElement.dataset.palette, false); });
        elements.language.addEventListener('click', () => setLanguage(state.language === 'zh' ? 'en' : 'zh'));
        elements.global_search.addEventListener('input', () => {
          clearTimeout(state.globalSearchTimer);
          abortActiveRequests('search');
          state.globalSearchTimer = setTimeout(() => performGlobalSearch().catch(() => {}), 180);
        });
        elements.global_search.addEventListener('focus', () => { if (elements.global_search_results.childElementCount) elements.global_search_results.classList.remove('hidden'); });
        elements.account_button.addEventListener('click', event => { event.stopPropagation(); togglePopover(elements.account_menu, elements.account_button); });
        elements.account_password.addEventListener('click', () => { togglePopover(elements.account_menu, elements.account_button, false); togglePasswordModal(true); });
        elements.account_security.addEventListener('click', () => { togglePopover(elements.account_menu, elements.account_button, false); location.hash = '#/sessions'; });
        elements.logout.addEventListener('click', logout);
        document.addEventListener('click', event => {
          if (!elements.appearance_popover.contains(event.target) && !elements.appearance_button.contains(event.target)) togglePopover(elements.appearance_popover, elements.appearance_button, false);
          if (!elements.account_menu.contains(event.target) && !elements.account_button.contains(event.target)) togglePopover(elements.account_menu, elements.account_button, false);
          if (!elements.global_search_shell.contains(event.target)) elements.global_search_results.classList.add('hidden');
          document.querySelectorAll('details.action-menu[open]').forEach(menu => { if (!menu.contains(event.target)) menu.removeAttribute('open'); });
        });
        elements.login.addEventListener('submit', login);
        elements.initial_password_form.addEventListener('submit', submitInitialPassword);
        elements.password_form.addEventListener('submit', submitAccountPassword);
        elements.password_modal_close.addEventListener('click', () => togglePasswordModal(false));
        elements.password_cancel.addEventListener('click', () => togglePasswordModal(false));
        elements.password_modal.addEventListener('click', event => { if (event.target === elements.password_modal) togglePasswordModal(false); });
        elements.new_user.addEventListener('click', () => openUserModal());
        elements.user_search.addEventListener('input', () => { state.userSearch = elements.user_search.value; renderUsers(); });
        elements.user_role_filter.addEventListener('change', () => { state.userRole = elements.user_role_filter.value; renderUsers(); });
        elements.user_form.addEventListener('submit', submitUser);
        elements.user_modal_close.addEventListener('click', closeUserModal);
        elements.user_cancel.addEventListener('click', closeUserModal);
        elements.user_modal.addEventListener('click', event => { if (event.target === elements.user_modal) closeUserModal(); });
        elements.reset_password_form.addEventListener('submit', submitResetPassword);
        elements.reset_password_close.addEventListener('click', closeResetPassword);
        elements.reset_password_cancel.addEventListener('click', closeResetPassword);
        elements.reset_password_modal.addEventListener('click', event => { if (event.target === elements.reset_password_modal) closeResetPassword(); });
        elements.totp_action.addEventListener('click', () => openTotpModal().catch(() => showToast(t('requestFailed'), true)));
        elements.totp_form.addEventListener('submit', submitTotp);
        elements.totp_modal_close.addEventListener('click', closeTotpModal);
        elements.totp_cancel.addEventListener('click', closeTotpModal);
        elements.totp_modal.addEventListener('click', event => { if (event.target === elements.totp_modal) closeTotpModal(); });
        elements.new_api_token.addEventListener('click', openApiTokenModal);
        elements.api_token_form.addEventListener('submit', submitApiToken);
        elements.api_token_close.addEventListener('click', closeApiTokenModal);
        elements.api_token_cancel.addEventListener('click', closeApiTokenModal);
        elements.api_token_copy.addEventListener('click', copyApiToken);
        elements.api_token_modal.addEventListener('click', event => { if (event.target === elements.api_token_modal) closeApiTokenModal(); });
        elements.new_fleet_peer.addEventListener('click', () => openFleetModal());
        elements.preview_fleet_sync.addEventListener('click', event => runFleetSync(true, event.currentTarget));
        elements.apply_fleet_sync.addEventListener('click', event => runFleetSync(false, event.currentTarget));
        elements.fleet_form.addEventListener('submit', submitFleetPeer);
        elements.fleet_modal_close.addEventListener('click', closeFleetModal);
        elements.fleet_cancel.addEventListener('click', closeFleetModal);
        elements.fleet_modal.addEventListener('click', event => { if (event.target === elements.fleet_modal) closeFleetModal(); });
        elements.traffic_control_form.addEventListener('submit', submitTrafficControl);
        elements.traffic_control_close.addEventListener('click', closeTrafficControl);
        elements.traffic_control_cancel.addEventListener('click', closeTrafficControl);
        elements.traffic_control_modal.addEventListener('click', event => { if (event.target === elements.traffic_control_modal) closeTrafficControl(); });
        elements.client_search.addEventListener('input', () => { state.clientSearch = elements.client_search.value; renderClients(); });
        elements.client_status_filter.addEventListener('change', () => { state.clientStatus = elements.client_status_filter.value; renderClients(); });
        elements.client_form.addEventListener('submit', submitClient);
        elements.client_modal_close.addEventListener('click', closeClientModal);
        elements.client_cancel.addEventListener('click', closeClientModal);
        elements.client_modal.addEventListener('click', event => { if (event.target === elements.client_modal) closeClientModal(); });
        elements.client_token_close.addEventListener('click', closeClientTokenModal);
        elements.client_token_done.addEventListener('click', closeClientTokenModal);
        elements.client_token_copy.addEventListener('click', copyClientToken);
        elements.client_token_modal.addEventListener('click', event => { if (event.target === elements.client_token_modal) closeClientTokenModal(); });
        elements.new_alert_rule.addEventListener('click', () => openAlertRuleModal());
        elements.alert_rule_form.addEventListener('submit', submitAlertRule);
        elements.alert_rule_close.addEventListener('click', closeAlertRuleModal);
        elements.alert_rule_cancel.addEventListener('click', closeAlertRuleModal);
        elements.alert_rule_modal.addEventListener('click', event => { if (event.target === elements.alert_rule_modal) closeAlertRuleModal(); });
        elements.check_server_update.addEventListener('click', checkServerUpdate);
        elements.download_server_update.addEventListener('click', downloadServerUpdate);
        elements.apply_server_update.addEventListener('click', applyServerUpdate);
        elements.refresh.addEventListener('click', () => loadManagementData({ forceHistory: true }));
        elements.overview_alert_more.addEventListener('click', () => { location.hash = '#/alerts'; });
        elements.export_metrics.addEventListener('click', () => { window.location.href = `/api/v1/metrics/history/export?range=${encodeURIComponent(state.trendRange)}&protocol=total&format=csv`; });
        elements.export_audit.addEventListener('click', () => { window.location.href = '/api/v1/audit/export?format=csv'; });
        document.querySelectorAll('a[href^="#/"]').forEach(link => link.addEventListener('click', event => {
          if (!state.drawer.open || !state.drawer.dirty) return;
          if (!window.confirm(t('cancel') + '?')) event.preventDefault();
          else cancelEdit(true);
        }));
        window.addEventListener('hashchange', () => {
          if (state.drawer.open) cancelEdit(true);
          state.selectedPolicies.clear();
          state.routeGeneration += 1;
          state.historyRequestGeneration += 1;
          abortActiveRequests('management');
          abortActiveRequests('history');
          state.historyActiveKey = null;
          state.historyPromise = null;
          state.loading = false;
          state.loadPromise = null;
          state.pendingLoad = false;
          renderRoute();
          loadManagementData({ forceHistory: true });
        });
        document.querySelectorAll('[data-trend-range]').forEach(button => button.addEventListener('click', () => {
          state.trendRange = button.dataset.trendRange;
          document.querySelectorAll('[data-trend-range]').forEach(item => item.classList.toggle('active', item === button));
          loadHistory(state.trendRange, 'total', { target: 'overview' }).catch(() => {});
        }));
        document.querySelectorAll('[data-service-range]').forEach(button => button.addEventListener('click', () => {
          state.serviceTrendRange = button.dataset.serviceRange;
          document.querySelectorAll('[data-service-range]').forEach(item => item.classList.toggle('active', item === button));
          loadHistory(state.serviceTrendRange, serviceHistoryProtocol(), { target: 'service' }).catch(() => {});
        }));
        elements.new_policy.addEventListener('click', () => openPolicyDrawer(state.route.service));
        elements.service_search.addEventListener('input', () => { state.serviceSearch = elements.service_search.value; renderServices(); });
        elements.service_status_filter.addEventListener('change', () => { state.serviceStatus = elements.service_status_filter.value; renderServices(); });
        elements.select_visible_policies.addEventListener('click', selectVisiblePolicies);
        elements.bulk_enable_policies.addEventListener('click', () => bulkSetPoliciesEnabled(true));
        elements.bulk_disable_policies.addEventListener('click', () => bulkSetPoliciesEnabled(false));
        elements.bulk_migrate_policies.addEventListener('click', bulkMigratePolicies);
        elements.bulk_delete_policies.addEventListener('click', bulkDeletePolicies);
        elements.export_policies.addEventListener('click', exportPolicies);
        elements.import_policies.addEventListener('click', () => elements.import_policies_file.click());
        elements.import_policies_file.addEventListener('change', importPoliciesFile);
        elements.policy_form.addEventListener('submit', submitPolicy);
        elements.policy_form.addEventListener('input', () => { state.drawer.dirty = true; state.drawer.values = collectDrawerValues(); updateDrawerConditions(); updateDrawerPortLabels(); });
        elements.drawer_close.addEventListener('click', () => cancelEdit());
        elements.drawer_cancel.addEventListener('click', () => cancelEdit());
        elements.drawer_backdrop.addEventListener('click', () => cancelEdit());
        elements.audit_search.addEventListener('input', () => { state.auditSearch = elements.audit_search.value; renderAudit(); });
        elements.audit_category.addEventListener('change', () => { state.auditCategory = elements.audit_category.value; renderAudit(); });
        elements.audit_load_more.addEventListener('click', () => { state.auditLimit = Math.min(100, state.auditLimit + 20); loadManagementData({ forceHistory: false }); });
        document.addEventListener('keydown', event => {
          if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
            event.preventDefault();
            elements.global_search.focus();
            return;
          }
          if (event.key === 'Escape') {
            if (!elements.traffic_control_modal.classList.contains('hidden')) return closeTrafficControl();
            if (!elements.fleet_modal.classList.contains('hidden')) return closeFleetModal();
            if (!elements.api_token_modal.classList.contains('hidden')) return closeApiTokenModal();
            if (!elements.totp_modal.classList.contains('hidden')) return closeTotpModal();
            if (!elements.alert_rule_modal.classList.contains('hidden')) return closeAlertRuleModal();
            if (!elements.client_token_modal.classList.contains('hidden')) return closeClientTokenModal();
            if (!elements.client_modal.classList.contains('hidden')) return closeClientModal();
            if (!elements.reset_password_modal.classList.contains('hidden')) return closeResetPassword();
            if (!elements.user_modal.classList.contains('hidden')) return closeUserModal();
            if (!elements.password_modal.classList.contains('hidden')) return togglePasswordModal(false);
            if (state.drawer.open) return cancelEdit();
            togglePopover(elements.appearance_popover, elements.appearance_button, false);
            togglePopover(elements.account_menu, elements.account_button, false);
          }
          if (event.key === 'Tab' && state.drawer.open) {
            const focusable = [...elements.policy_drawer.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled)')];
            if (!focusable.length) return;
            const first = focusable[0], last = focusable.at(-1);
            if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
            else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
          }
        });
        window.addEventListener('resize', scheduleResponsiveRender, { passive: true });
        document.addEventListener('visibilitychange', () => {
          if (!document.hidden && state.identity) loadManagementData({ forceHistory: false }).catch(() => {});
        });
        setupTrafficTooltip();
        setupChartResizeObserver();
        setupPixelRatioObserver();
      }

      function safeStorageGet(key, fallback = null) {
        try { return localStorage.getItem(key) ?? fallback; } catch (_) { return fallback; }
      }
      function safeStorageSet(key, value) { try { localStorage.setItem(key, value); } catch (_) {} }

      state.sessionGeneration = 0;
      state.routeGeneration = 0;
      state.loadPromise = null;
      state.historyMeta = null;
      state.trendRange = '1h';
      state.serviceTrendRange = '1h';
      state.language = safeStorageGet('linklake-language', state.language);
      bindEvents();
      applyTheme(document.documentElement.dataset.themeMode, document.documentElement.dataset.palette, false);
      updateThemeButtons();
      applyLanguage();
      loadIdentity();
