import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Divider,
  Grid,
  LinearProgress,
  MenuItem,
  Stack,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  Typography,
} from '@mui/material';
import {
  Gavel as GavelIcon,
  LibraryBooks as LibraryBooksIcon,
  Lock as LockIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material';
import { apiClient as axios } from '../../config/api';

const ACTION_COLOR = {
  blocked: 'error',
  quarantined: 'warning',
  confirm: 'warning',
  would_block: 'info',
  would_quarantine: 'info',
};

// The three layers around Cracky, in the order a request meets them.
const FIREWALLS = [
  {
    id: 'kb',
    name: 'KB firewall',
    icon: LibraryBooksIcon,
    what: 'What goes in',
    blurb: 'Scans knowledge-base entries when they are written and every passage before it reaches the chatbot, '
      + 'including instructions split across several entries. Poisoned text is quarantined or dropped; the rest '
      + 'reaches the model as quoted data.',
    stats: (s) => [
      ['Passages scanned', s?.counters?.chunks_scanned],
      ['Passages blocked', s?.counters?.chunks_blocked],
      ['Split payloads', s?.counters?.split_payloads],
      ['Entries quarantined', s?.counters?.writes_quarantined],
    ],
  },
  {
    id: 'action',
    name: 'Action firewall',
    icon: GavelIcon,
    what: 'What it may do',
    blurb: 'Checks refunds, coupons, exports and order changes in the request and the reply against the account '
      + 'behind the login: its own orders, its role and the refund limit. Five languages, hidden-text tricks undone.',
    stats: (s) => [
      ['Actions blocked', s?.firewalls?.action?.counts?.blocked],
      ['Sent for staff approval', s?.firewalls?.action?.counts?.confirm],
    ],
  },
  {
    id: 'leak',
    name: 'Leak firewall',
    icon: LockIcon,
    what: 'What comes out',
    blurb: 'Compares every reply with the system prompt that was sent. Credentials, keys, flags, internal paths, '
      + 'restricted codes and other customers’ records are refused, even spaced out, reversed or encoded.',
    stats: (s) => [['Leaks stopped', s?.firewalls?.leak?.counts?.blocked]],
  },
];
const FIREWALL_NAME = Object.fromEntries(FIREWALLS.map((f) => [f.id, f.name.replace(' firewall', '')]));

// Pages in this app attach the token per request.
const auth = (extra = {}) => ({ ...extra, headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } });

const RiskBar = ({ risk }) => (
  <Box sx={{ minWidth: 90 }}>
    <LinearProgress
      variant="determinate"
      value={Math.round((risk || 0) * 100)}
      color={risk >= 0.6 ? 'error' : risk >= 0.3 ? 'warning' : 'success'}
      sx={{ height: 8, borderRadius: 1 }}
    />
    <Typography variant="caption" color="text.secondary">{(risk ?? 0).toFixed(2)}</Typography>
  </Box>
);

const Reasons = ({ reasons }) => (
  <Stack direction="row" spacing={0.5} useFlexGap flexWrap="wrap">
    {(reasons || []).map((r) => (
      <Chip
        key={r}
        label={r}
        size="small"
        variant="outlined"
        sx={{ maxWidth: '100%', height: 'auto', '& .MuiChip-label': { whiteSpace: 'normal', py: 0.25 } }}
      />
    ))}
  </Stack>
);

// Long snippets are cut to three lines; the full text is in the backend log.
const Snippet = ({ text }) => (
  <Typography
    variant="caption"
    color="text.secondary"
    title={text}
    sx={{ display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}
  >
    {text}
  </Typography>
);

const where = (e) => {
  if (e.firewall === 'kb') return e.kind === 'write' ? `write by ${e.user || '?'}` : e.surface;
  const who = e.user ? ` · ${e.user}` : '';
  return `${e.surface || ''} ${e.stage || ''}${who} · L${e.level ?? '?'}`;
};

const EventDetail = ({ e }) => {
  if (e.firewall === 'kb') {
    return (
      <>
        <Typography variant="body2" fontWeight={600}>{e.title}</Typography>
        <Snippet text={e.snippet} />
        {e.risk !== undefined && <RiskBar risk={e.risk} />}
      </>
    );
  }
  if (e.firewall === 'leak') {
    return (
      <Stack direction="row" spacing={0.5} useFlexGap flexWrap="wrap">
        {(e.secrets || []).map((s) => <Chip key={s} label={s} size="small" color="error" variant="outlined" />)}
        {e.copied > 0 && <Chip label={`${e.copied} copied run(s)`} size="small" variant="outlined" />}
      </Stack>
    );
  }
  return (
    <>
      <Typography variant="body2" fontWeight={600}>{(e.kinds || []).join(', ').replace(/_/g, ' ')}</Typography>
      <Snippet text={e.snippet} />
    </>
  );
};

const FirewallCard = ({ fw, status, enabled, onToggle, onMode }) => {
  const Icon = fw.icon;
  const levels = status?.firewalls?.[fw.id]?.levels || [];
  return (
    <Card variant="outlined" sx={{ height: '100%', borderColor: enabled ? 'success.main' : undefined }}>
      <CardContent>
        <Stack direction="row" alignItems="center" spacing={1}>
          <Icon color={enabled ? 'success' : 'disabled'} />
          <Typography variant="h6" fontWeight={700} sx={{ flexGrow: 1 }}>{fw.name}</Typography>
          <Switch
            checked={enabled}
            onChange={(e) => onToggle(e.target.checked)}
            inputProps={{ 'aria-label': `${fw.name} on or off` }}
          />
        </Stack>
        <Stack direction="row" spacing={0.5} sx={{ mb: 1 }}>
          <Chip size="small" label={fw.what} />
          <Chip size="small" variant="outlined" label={`Levels ${levels.join(', ')}`} />
        </Stack>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{fw.blurb}</Typography>
        {fw.id === 'kb' && (
          <>
            <TextField
              select
              size="small"
              label="Mode"
              value={status?.mode || 'block'}
              onChange={(e) => onMode(e.target.value)}
              sx={{ mb: 1, minWidth: 220 }}
            >
              <MenuItem value="block">Block and quarantine</MenuItem>
              <MenuItem value="monitor">Monitor only (log, don't block)</MenuItem>
            </TextField>
            <Typography variant="caption" color="text.secondary" component="div" sx={{ mb: 1 }}>
              Embedding model: {status?.semantic_model || 'loads on first scan'}
              {status?.semantic_model && !status?.semantic_multilingual ? ' (English; other languages via patterns)' : ''}
            </Typography>
          </>
        )}
        <Divider sx={{ mb: 1 }} />
        <Stack direction="row" spacing={2} useFlexGap flexWrap="wrap">
          {fw.stats(status).map(([label, value]) => (
            <Box key={label}>
              <Typography variant="h5" fontWeight={700}>{value ?? 0}</Typography>
              <Typography variant="caption" color="text.secondary">{label}</Typography>
            </Box>
          ))}
        </Stack>
      </CardContent>
    </Card>
  );
};

const KbFirewallPage = () => {
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [filter, setFilter] = useState('all');
  const [quarantine, setQuarantine] = useState([]);
  const [error, setError] = useState('');
  const [scanText, setScanText] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const params = { limit: 100, ...(filter === 'all' ? {} : { firewall: filter }) };
      const [s, e, q] = await Promise.all([
        axios.get('/api/kb-firewall/status', auth()),
        axios.get('/api/kb-firewall/events', auth({ params })),
        axios.get('/api/kb-firewall/quarantine', auth()),
      ]);
      setStatus(s.data);
      setEvents(e.data.events || []);
      setQuarantine(q.data.entries || []);
      setError('');
    } catch (err) {
      setError(err.response?.status === 403 ? 'Admin access required.' : 'Could not reach the firewall API.');
    }
  }, [filter]);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, [refresh]);

  const toggle = async (body) => {
    try {
      const res = await axios.post('/api/kb-firewall/toggle', body, auth());
      setStatus(res.data);
    } catch {
      setError('Could not change the firewall setting.');
    }
  };

  const release = async (id) => {
    await axios.post(`/api/kb-firewall/quarantine/${id}/release`, {}, auth());
    refresh();
  };

  const clearLog = async () => {
    await axios.delete('/api/kb-firewall/events', auth());
    refresh();
  };

  const runScan = async () => {
    setScanning(true);
    try {
      const res = await axios.post('/api/kb-firewall/scan', { text: scanText }, auth());
      setScanResult(res.data);
    } finally {
      setScanning(false);
    }
  };

  const enabled = {
    kb: !!status?.enabled,
    action: !!status?.firewalls?.action?.enabled,
    leak: !!status?.firewalls?.leak?.enabled,
  };
  const onCount = Object.values(enabled).filter(Boolean).length;
  const switchBody = {
    kb: (on) => ({ enabled: on, mode: status?.mode }),
    action: (on) => ({ action_enabled: on }),
    leak: (on) => ({ leak_enabled: on }),
  };

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Stack direction="row" alignItems="center" spacing={1.5} sx={{ mb: 1 }}>
        <ShieldIcon color={onCount ? 'success' : 'disabled'} fontSize="large" />
        <Typography variant="h4" fontWeight={700}>AI Goat Firewall</Typography>
        <Chip label={`${onCount} of 3 layers on`} color={onCount === 3 ? 'success' : onCount ? 'warning' : 'default'} />
      </Stack>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Three layers around Cracky, each checked in code rather than by asking the model: what goes into its prompt,
        what it is allowed to do, and what it says back. Switches take effect immediately; Level 0 stays vulnerable for
        the labs.
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Grid container spacing={2} sx={{ mb: 3 }}>
        {FIREWALLS.map((fw) => (
          <Grid item xs={12} md={4} key={fw.id}>
            <FirewallCard
              fw={fw}
              status={status}
              enabled={enabled[fw.id]}
              onToggle={(on) => toggle(switchBody[fw.id](on))}
              onMode={(mode) => toggle({ enabled: enabled.kb, mode })}
            />
          </Grid>
        ))}
      </Grid>

      <Card variant="outlined" sx={{ mb: 3 }}>
        <CardContent>
          <Stack direction="row" justifyContent="space-between" alignItems="center" useFlexGap flexWrap="wrap">
            <Typography variant="h6" fontWeight={600}>Live log</Typography>
            <Stack direction="row" alignItems="center" spacing={1}>
              <Tabs value={filter} onChange={(_, v) => setFilter(v)} sx={{ minHeight: 36 }}>
                <Tab value="all" label="All" sx={{ minHeight: 36 }} />
                {FIREWALLS.map((fw) => (
                  <Tab key={fw.id} value={fw.id} label={FIREWALL_NAME[fw.id]} sx={{ minHeight: 36 }} />
                ))}
              </Tabs>
              <Button size="small" onClick={clearLog}>Clear</Button>
            </Stack>
          </Stack>
          {events.length === 0 ? (
            <Typography color="text.secondary" sx={{ py: 2 }}>Nothing logged yet.</Typography>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <Table size="small" sx={{ tableLayout: 'fixed', minWidth: 880 }}>
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ width: 76 }}>Time</TableCell>
                    <TableCell sx={{ width: 82 }}>Layer</TableCell>
                    <TableCell sx={{ width: 120 }}>Action</TableCell>
                    <TableCell sx={{ width: 150 }}>Where</TableCell>
                    <TableCell sx={{ width: '32%' }}>What</TableCell>
                    <TableCell>Why</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {events.map((e, i) => (
                    <TableRow key={`${e.at}-${i}`} sx={{ verticalAlign: 'top' }}>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>{(e.at || '').slice(11)}</TableCell>
                      <TableCell><Chip size="small" variant="outlined" label={FIREWALL_NAME[e.firewall] || e.firewall} /></TableCell>
                      <TableCell><Chip size="small" label={e.action} color={ACTION_COLOR[e.action] || 'default'} /></TableCell>
                      <TableCell sx={{ wordBreak: 'break-word' }}>{where(e)}</TableCell>
                      <TableCell sx={{ wordBreak: 'break-word' }}><EventDetail e={e} /></TableCell>
                      <TableCell><Reasons reasons={e.reasons} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          )}
        </CardContent>
      </Card>

      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" fontWeight={600}>KB quarantine</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Held back from the chatbot until a reviewer releases them.
              </Typography>
              {quarantine.length === 0 && <Typography color="text.secondary">Empty.</Typography>}
              {quarantine.map((q) => (
                <Box key={q.id} sx={{ py: 1 }}>
                  <Divider sx={{ mb: 1 }} />
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography fontWeight={600}>#{q.id} {q.title}</Typography>
                    <Button size="small" variant="outlined" onClick={() => release(q.id)}>Release</Button>
                  </Stack>
                  <Typography variant="body2" color="text.secondary" sx={{ my: 0.5 }}>{q.content}</Typography>
                  <RiskBar risk={q.risk} />
                  <Reasons reasons={q.reasons} />
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" fontWeight={600}>Try the KB scanner</Typography>
              <TextField
                multiline
                minRows={4}
                fullWidth
                placeholder="Paste any knowledge-base text, in any language"
                value={scanText}
                onChange={(e) => setScanText(e.target.value)}
                sx={{ my: 1 }}
              />
              <Button variant="contained" onClick={runScan} disabled={!scanText.trim() || scanning}>
                {scanning ? 'Scanning…' : 'Scan'}
              </Button>
              {scanResult && (
                <Box sx={{ mt: 2 }}>
                  <Alert severity={scanResult.flagged ? 'error' : 'success'} sx={{ mb: 1 }}>
                    {scanResult.flagged ? 'Would be blocked' : 'Would be allowed'} · risk {scanResult.risk.toFixed(2)}
                  </Alert>
                  {scanResult.signals.map((s) => (
                    <Typography key={s.label} variant="body2" sx={{ mb: 0.5 }}>
                      <b>{s.label}</b> (+{s.weight.toFixed(2)}, {s.source}): <i>{s.evidence}</i>
                    </Typography>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Container>
  );
};

export default KbFirewallPage;
