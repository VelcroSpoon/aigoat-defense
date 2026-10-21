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
  FormControlLabel,
  Grid,
  LinearProgress,
  MenuItem,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { Shield as ShieldIcon } from '@mui/icons-material';
import { apiClient as axios } from '../../config/api';

const ACTION_COLOR = {
  blocked: 'error',
  quarantined: 'warning',
  would_block: 'info',
  would_quarantine: 'info',
};

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
    {(reasons || []).map((r) => <Chip key={r} label={r} size="small" variant="outlined" />)}
  </Stack>
);

const KbFirewallPage = () => {
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [quarantine, setQuarantine] = useState([]);
  const [error, setError] = useState('');
  const [scanText, setScanText] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, e, q] = await Promise.all([
        axios.get('/api/kb-firewall/status', auth()),
        axios.get('/api/kb-firewall/events', auth({ params: { limit: 50 } })),
        axios.get('/api/kb-firewall/quarantine', auth()),
      ]);
      setStatus(s.data);
      setEvents(e.data.events || []);
      setQuarantine(q.data.entries || []);
      setError('');
    } catch (err) {
      setError(err.response?.status === 403 ? 'Admin access required.' : 'Could not reach the KB Firewall API.');
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  }, [refresh]);

  const toggle = async (enabled, mode) => {
    const res = await axios.post('/api/kb-firewall/toggle', { enabled, mode: mode || status?.mode }, auth());
    setStatus(res.data);
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

  const on = !!status?.enabled;

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Stack direction="row" alignItems="center" spacing={1.5} sx={{ mb: 1 }}>
        <ShieldIcon color={on ? 'success' : 'disabled'} fontSize="large" />
        <Typography variant="h4" fontWeight={700}>KB Firewall</Typography>
        <Chip
          label={on ? (status.mode === 'block' ? 'ON · blocking' : 'ON · monitor only') : 'OFF'}
          color={on ? (status.mode === 'block' ? 'success' : 'info') : 'default'}
        />
      </Stack>
      <Typography color="text.secondary" sx={{ mb: 3 }}>
        Scans knowledge-base entries when they are written and every passage before it reaches the chatbot.
        Passages that carry hidden instructions are quarantined or dropped; the rest are passed to the model as quoted data.
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} md={5}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <FormControlLabel
                control={<Switch checked={on} onChange={(e) => toggle(e.target.checked)} />}
                label={<Typography fontWeight={600}>Protection {on ? 'enabled' : 'disabled'}</Typography>}
              />
              <TextField
                select
                size="small"
                label="Mode"
                value={status?.mode || 'block'}
                onChange={(e) => toggle(on, e.target.value)}
                sx={{ mt: 2, minWidth: 200 }}
              >
                <MenuItem value="block">Block and quarantine</MenuItem>
                <MenuItem value="monitor">Monitor only (log, don't block)</MenuItem>
              </TextField>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                Embedding model: {status?.semantic_model || 'loads on first scan'}
                {status?.semantic_model && !status?.semantic_multilingual ? ' (English; other languages via patterns)' : ''}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        {[
          ['Passages scanned', status?.counters?.chunks_scanned],
          ['Passages blocked', status?.counters?.chunks_blocked],
          ['Entries quarantined', status?.counters?.writes_quarantined],
        ].map(([label, value]) => (
          <Grid item xs={4} md={7 / 3} key={label}>
            <Card variant="outlined" sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h4" fontWeight={700}>{value ?? 0}</Typography>
                <Typography variant="body2" color="text.secondary">{label}</Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Card variant="outlined" sx={{ mb: 3 }}>
        <CardContent>
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Typography variant="h6" fontWeight={600}>Live log</Typography>
            <Button size="small" onClick={clearLog}>Clear</Button>
          </Stack>
          {events.length === 0 ? (
            <Typography color="text.secondary" sx={{ py: 2 }}>Nothing blocked yet.</Typography>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Time</TableCell>
                  <TableCell>Where</TableCell>
                  <TableCell>Action</TableCell>
                  <TableCell>Risk</TableCell>
                  <TableCell>Entry</TableCell>
                  <TableCell>Why</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {events.map((e, i) => (
                  <TableRow key={`${e.at}-${i}`}>
                    <TableCell sx={{ whiteSpace: 'nowrap' }}>{(e.at || '').slice(11)}</TableCell>
                    <TableCell>{e.kind === 'write' ? `write by ${e.user || '?'}` : e.surface}</TableCell>
                    <TableCell><Chip size="small" label={e.action} color={ACTION_COLOR[e.action] || 'default'} /></TableCell>
                    <TableCell><RiskBar risk={e.risk} /></TableCell>
                    <TableCell sx={{ maxWidth: 260 }}>
                      <Typography variant="body2" fontWeight={600}>{e.title}</Typography>
                      <Typography variant="caption" color="text.secondary">{e.snippet}</Typography>
                    </TableCell>
                    <TableCell><Reasons reasons={e.reasons} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" fontWeight={600}>Quarantine</Typography>
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
              <Typography variant="h6" fontWeight={600}>Try the scanner</Typography>
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
                      <b>{s.label}</b> (+{s.weight.toFixed(2)}, {s.source}) — <i>{s.evidence}</i>
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
