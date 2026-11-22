'use strict';
/* Privacy-Preserving Multi-Agent Communication — native-browser controller.
 * Security decisions come from the Python API. CSS/SVG visuals never determine
 * whether an attack was blocked. No mock or fake success fallback.
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const qa = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const attackNames = {
    tamper: 'Ciphertext tampering', replay: 'Replay injection',
    impersonation: 'Identity spoofing', decryption: 'Unauthorized decryption',
    oversized: 'Oversized packet', flood: 'Message flood',
  };
  const defenseNames = {
    tamper: 'Ed25519 signature + AES-GCM authentication',
    replay: 'Message-ID replay cache + timestamp window',
    impersonation: 'Pinned sender signing identity',
    decryption: 'X25519 recipient key + AES-256-GCM',
    oversized: 'Message and TCP frame-size limits',
    flood: 'Per-sender sliding-window rate limit',
  };
  const keys = Object.keys(attackNames);
  const state = {
    page: 'overview', attack: 'tamper', result: null, position: 0,
    timer: null, paused: false, busy: false, current: null, requestVersion: 0,
    activeMessageId: null, audit: [], auditSelectedId: null,
  };

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  }
  function clear(node) { node.replaceChildren(); }
  function alert(message) {
    const banner = $('alertBanner'); banner.textContent = message; banner.hidden = false;
  }
  function clearAlert() { $('alertBanner').hidden = true; }
  async function api(path, body) {
    const options = { cache: 'no-store', credentials: 'same-origin' };
    if (body !== undefined) {
      options.method = 'POST'; options.headers = {'Content-Type': 'application/json'};
      options.body = JSON.stringify(body);
    }
    let response;
    try { response = await fetch(path, options); }
    catch (_) { throw new Error('Cannot reach the local Python server. Start it with: python main.py --web'); }
    let data;
    try { data = await response.json(); }
    catch (_) { throw new Error('Server returned an unreadable response'); }
    if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
    return data;
  }

  function page(name) {
    if (!$('page-' + name)) return;
    state.page = name;
    qa('.page').forEach(node => node.classList.toggle('active', node.id === 'page-' + name));
    qa('.nav-item').forEach(node => {
      const active = node.dataset.page === name;
      node.classList.toggle('active', active);
      if (active) node.setAttribute('aria-current', 'page'); else node.removeAttribute('aria-current');
    });
    clearAlert();
    window.scrollTo({top: 0, behavior: 'smooth'});
    if (name === 'analytics' || name === 'simulator' || name === 'overview') refresh();
    if (name === 'simulator') loadInbox();
    if (name === 'crypto') refreshAudit();
  }
  qa('.nav-item').forEach(button => button.addEventListener('click', () => page(button.dataset.page)));
  qa('[data-go]').forEach(button => button.addEventListener('click', () => page(button.dataset.go)));

  function setConnection(online) {
    $('serverLight').className = `server-light ${online ? 'online' : 'offline'}`;
    $('connectionStatus').textContent = online ? 'PYTHON ENGINE / ONLINE' : 'PYTHON ENGINE / OFFLINE';
  }
  function updateSelect(select, names, previousValue) {
    const keep = previousValue || select.value;
    clear(select);
    names.forEach(name => {
      const opt = element('option', '', name); opt.value = name; select.append(opt);
    });
    if (names.includes(keep)) select.value = keep;
  }
  function renderNetwork(agents) {
    const svg = $('liveNetworkSvg'); clear(svg);
    const ns = 'http://www.w3.org/2000/svg';
    function shape(tag, attrs, label) {
      const node = document.createElementNS(ns, tag);
      for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, String(value));
      if (label !== undefined) node.textContent = String(label);
      svg.append(node); return node;
    }
    const trusted = agents.filter(a => a.role === 'trusted');
    const positions = Object.fromEntries(trusted.map((a, i) => {
      const col = i % 6, row = Math.floor(i / 6);
      const span = Math.min(6, trusted.length - row * 6);
      return [a.name, {x: (920 / (span + 1)) * (col + 1), y: trusted.length > 6 ? 75 + row * 83 : 139}];
    }));
    shape('path', {d:'M30 210 H890 M460 20V220', stroke:'#628e72', 'stroke-opacity':'.17', fill:'none'});
    const names = Object.keys(positions);
    for (let i=0; i<names.length; i++) {
      for (let j=i+1; j<names.length; j++) {
        const a=positions[names[i]], b=positions[names[j]];
        shape('line',{x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:'#678b6e','stroke-opacity':'.23','stroke-width':1,'stroke-dasharray':'3 8'});
      }
    }
    const selected = (state.current?.messages || []).find(x => x.id === $('targetMessageSelect').value);
    if (selected && positions[selected.sender] && positions[selected.recipient]) {
      const a = positions[selected.sender], b = positions[selected.recipient];
      const d = `M${a.x} ${a.y} Q${(a.x+b.x)/2} ${Math.min(a.y,b.y)-72} ${b.x} ${b.y}`;
      shape('path',{d,stroke:'#d8fa54','stroke-width':2.8,fill:'none','stroke-dasharray':'6 6',opacity:'.9'});
      const pulse=shape('circle',{r:6,fill:'#d8fa54',class:'route-pulse'});
      const motion = document.createElementNS(ns,'animateMotion');
      motion.setAttribute('dur','3s');motion.setAttribute('repeatCount','indefinite');motion.setAttribute('path',d);
      pulse.append(motion);
      $('currentRouteMeta').textContent = `${selected.sender} → ${selected.recipient} / ${selected.id.slice(0,12)}`;
      $('simSenderInitial').textContent = selected.sender[0].toUpperCase();
      $('simSenderCaption').textContent = selected.sender.toUpperCase();
      $('simRecipientInitial').textContent = selected.recipient[0].toUpperCase();
      $('simRecipientCaption').textContent = selected.recipient.toUpperCase();
    } else {
      $('currentRouteMeta').textContent = `${trusted.length} trusted agents / no message selected`;
      $('simSenderInitial').textContent = 'A'; $('simSenderCaption').textContent = 'SENDER';
      $('simRecipientInitial').textContent = 'B'; $('simRecipientCaption').textContent = 'RECIPIENT';
    }
    for (const agent of trusted) {
      const {x,y}=positions[agent.name];
      shape('circle',{cx:x,cy:y,r:31,fill:'none',stroke:'#bddb9b','stroke-dasharray':'3 4',opacity:'.6'});
      shape('circle',{cx:x,cy:y,r:21,fill:'#d8fa54'});
      shape('text',{x,y:y+5,'text-anchor':'middle',fill:'#163b2c','font-weight':900,'font-size':16},agent.name[0].toUpperCase());
      shape('text',{x,y:y+45,'text-anchor':'middle',fill:'#e7f3dc','font-size':11,'font-family':'monospace'},agent.name);
    }
    const eve=agents.find(a => a.role === 'untrusted');
    if (eve) {
      shape('circle',{cx:460,cy:20,r:14,fill:'#fa674d'});
      shape('text',{x:460,y:25,'text-anchor':'middle','font-size':11,'font-weight':900,fill:'#1b392b'},'E');
      shape('text',{x:485,y:24,'font-size':10,fill:'#ffb8a5'},'UNTRUSTED / ' + eve.name);
    }
  }
  function renderMessageTargets(messages) {
    const select = $('targetMessageSelect');
    const wanted = state.activeMessageId || select.value;
    clear(select);
    if (!messages.length) {
      const option = element('option','', 'Send a message first…'); option.value=''; select.append(option);
    } else {
      for (const msg of messages) {
        const option = element('option','',`${msg.sender} → ${msg.recipient} / ${msg.id.slice(0,12)} / ${msg.status}`);
        option.value=msg.id; select.append(option);
      }
      if (messages.some(x=>x.id===wanted)) select.value=wanted;
    }
    state.activeMessageId = select.value || null;
    renderNetwork(state.current?.agents || []);
  }
  $('targetMessageSelect').addEventListener('change', () => {
    state.activeMessageId = $('targetMessageSelect').value;
    renderNetwork(state.current?.agents || []);
    setAttack(state.attack);
  });
  function renderAgents(agents) {
    const trusted = agents.filter(agent => agent.role === 'trusted').map(agent => agent.name);
    const previousSender = $('senderSelect').value;
    const previousRecipient = $('recipientSelect').value;
    updateSelect($('senderSelect'), trusted, previousSender || 'Alice');
    updateSelect($('recipientSelect'), trusted, previousRecipient || 'Bob');
    if ($('senderSelect').value === $('recipientSelect').value && trusted.length > 1)
      $('recipientSelect').value = trusted.find(n => n !== $('senderSelect').value);
    const currentInbox = $('inboxAgentSelect').value;
    updateSelect($('inboxAgentSelect'), trusted, currentInbox || 'Bob');
    const grid = $('agentGrid'); clear(grid);
    agents.forEach(agent => {
      const card = element('article', 'agent-card ' + (agent.role === 'trusted' ? '' : 'untrusted'));
      card.append(element('div', 'agent-avatar', agent.name[0].toUpperCase()));
      card.append(element('strong', '', agent.name));
      card.append(element('small', 'trust-status', agent.role === 'trusted' ? '● TRUSTED LOCAL IDENTITY' : '● UNTRUSTED ADVERSARY'));
      card.append(element('small', '', 'PIN: ' + agent.fingerprint));
      card.append(element('small', '', 'TRUSTED PEERS: ' + agent.peer_count));
      card.append(element('small', '', 'LOCAL PORT: ' + agent.port));
      grid.append(card);
    });
  }
  function renderEvents(events) {
    const journal = $('eventJournal'); clear(journal);
    if (!events.length) { journal.append(element('p', 'muted', 'No events recorded.')); return; }
    events.forEach(ev => {
      const row = element('div', 'event-item ' + (ev.level || ''));
      row.append(element('span', '', ev.time));
      row.append(element('b', '', ev.category));
      row.append(element('div', '', ev.message));
      journal.append(row);
    });
  }
  function renderAnalytics(snapshot) {
    const m = snapshot.metrics;
    $('analyticRuns').textContent = m.attack_runs;
    $('analyticBlocked').textContent = m.attacks_blocked;
    $('analyticHypothetical').textContent = m.hypothetical_compromises;
    const chart = $('attackChart'); clear(chart);
    const counts = Object.fromEntries(keys.map(k => [k, 0]));
    snapshot.experiments.forEach(exp => { if (exp.attack in counts) counts[exp.attack]++; });
    const max = Math.max(1, ...Object.values(counts));
    keys.forEach(key => {
      const row = element('div', 'bar-item');
      row.append(element('span', '', attackNames[key]));
      const track = element('div', 'bar-track'); const fill = element('div', 'bar-fill');
      fill.style.width = `${Math.round(100 * counts[key] / max)}%`;
      track.append(fill); row.append(track); row.append(element('b', '', counts[key])); chart.append(row);
    });
    const history = $('experimentHistory'); clear(history);
    if (!snapshot.experiments.length) history.append(element('p', 'muted', 'No experiment results yet.'));
    snapshot.experiments.forEach(exp => {
      const row = element('div', 'history-item');
      const left = element('div');
      left.append(element('strong', '', exp.label), element('div', '', exp.observed_status));
      row.append(left, element('small', '', exp.time + ' / ' + (exp.defenses_enabled ? 'CHECKED' : 'WHAT-IF')));
      history.append(row);
    });
  }
  async function refresh() {
    try {
      const snapshot = await api('/api/state'); state.current = snapshot;
      setConnection(true);
      $('overviewBackendState').textContent = 'ONLINE / LOCAL TCP';
      $('trustStateText').textContent = `${snapshot.metrics.trusted_agents} TRUSTED IDENTITIES / ${snapshot.metrics.delivered_messages} DELIVERED MESSAGES`;
      $('kpiAgents').textContent = snapshot.metrics.trusted_agents.toString().padStart(2, '0');
      $('kpiMessages').textContent = snapshot.metrics.delivered_messages.toString().padStart(2, '0');
      $('kpiExperiments').textContent = snapshot.metrics.attack_runs.toString().padStart(2, '0');
      renderAgents(snapshot.agents);
      renderMessageTargets(snapshot.messages || []);
      renderEvents(snapshot.events);
      renderAnalytics(snapshot);
    } catch (error) { setConnection(false); $('overviewBackendState').textContent='OFFLINE'; alert(error.message); }
  }

  const theater = $('simTheater');
  function stopPlayback() { if (state.timer !== null) window.clearTimeout(state.timer); state.timer = null; }
  function setAttack(key) {
    if (!attackNames[key]) return;
    stopPlayback(); state.requestVersion++; state.attack = key; state.position = 0; state.result = null;
    state.paused = false; theater.dataset.attack = key;
    theater.dataset.stage = '0'; theater.classList.remove('is-paused');
    $('theaterNumber').textContent = `TEST / ${String(keys.indexOf(key) + 1).padStart(2, '0')}`;
    $('proofDefense').textContent = defenseNames[key];
    qa('.attack-choice').forEach(button => button.classList.toggle('selected', button.dataset.attack === key));
    $('simVerdict').textContent = 'AWAITING EXPERIMENT';
    $('simVerdict').className = '';
    $('simPhase').textContent = 'Run to inspect the cryptographic checks.';
    $('proofCode').textContent = 'NO RUN RECORDED';
    $('proofDetail').textContent = 'The Python library determines the result; visuals are explanatory.';
    $('stepCount').textContent = '0 / 0';
    clear($('attackTimeline'));
    $('attackTimeline').append(element('li', '', 'Run an experiment to view its evidence.'));
    $('pauseAttack').textContent = 'Ⅱ PAUSE';
  }
  qa('.attack-choice').forEach(button => button.addEventListener('click', () => setAttack(button.dataset.attack)));
  $('defensesEnabled').addEventListener('change', () => setAttack(state.attack));

  function renderStage() {
    const r = state.result; if (!r) return;
    const n = r.stages.length; const current = state.position;
    theater.dataset.stage = String(current);
    $('stepCount').textContent = `${current} / ${n}`;
    const list = $('attackTimeline'); clear(list);
    r.stages.forEach((item, i) => {
      const li = element('li', [i < current ? 'done' : 'pending', item.tone || 'neutral'].join(' '));
      li.dataset.num = String(i + 1).padStart(2, '0');
      li.append(element('strong', '', item.title));
      li.append(element('span', '', item.actor + ' — ' + item.detail));
      list.append(li);
    });
    $('simPhase').textContent = current > 0 ? r.stages[current - 1].detail : 'Ready to inspect packet evidence.';
    if (current >= n) {
      stopPlayback();
      const label = r.verdict === 'BLOCKED' ? 'THREAT BLOCKED' : r.verdict === 'HYPOTHETICAL_BREACH' ? 'WHAT-IF: BREACH' : 'VERIFY CHECK FAILED';
      $('simVerdict').textContent = label;
      $('simVerdict').className = r.actual_blocked && r.defenses_enabled ? 'secure' : 'risky';
      $('proofCode').textContent = 'TARGET / ' + (r.target_message_id || 'ISOLATED SAMPLE') + '\n' + 'AGENTS / ' + r.sender + ' → ' + r.recipient + '\n' + 'OBSERVED / ' + r.observed_status + '\n' + 'DISPLAY / ' + r.verdict + '\n' + 'MODE / ' + r.mode + (Object.keys(r.checks).length ? '\n' + JSON.stringify(r.checks) : '');
      $('proofDetail').textContent = (r.isolation_note || '') + (r.defenses_enabled ? ' The rejection code was produced by actual Python cryptographic checks.' : ' The breach outcome is only hypothetical; real defenses remain enabled.');
    } else {
      $('simVerdict').textContent = 'ANALYZING PACKET'; $('simVerdict').className = '';
      $('proofCode').textContent = 'RUN / ' + r.id + '\n' + 'SIGNAL / ' + (current ? r.stages[current - 1].title.toUpperCase() : 'STARTED');
    }
  }
  function scheduleNext() {
    stopPlayback();
    if (state.paused || !state.result || state.position >= state.result.stages.length) return;
    const speed = Number($('speedControl').value) || 1;
    state.timer = window.setTimeout(() => {
      if (!state.result || state.paused) return;
      state.position++;
      renderStage(); scheduleNext();
    }, Math.round(950 / speed));
  }
  $('runAttack').addEventListener('click', async () => {
    if (state.busy) return;
    state.busy = true; $('runAttack').disabled = true; clearAlert(); stopPlayback();
    state.result = null; state.position = 0; state.paused = false;
    theater.classList.remove('is-paused');
    $('pauseAttack').textContent = 'Ⅱ PAUSE';
    const requestVersion = ++state.requestVersion;
    $('simVerdict').textContent = 'RUNNING LIBRARY CHECKS…';
    try {
      const attack = state.attack;
      const enabled = $('defensesEnabled').checked;
      const message_id = $('targetMessageSelect').value;
      if (!message_id) throw new Error('Send an encrypted message first, then choose it as the attack target.');
      const result = await api('/api/simulations', {attack, defenses_enabled: enabled, message_id});
      if (state.attack !== attack || state.requestVersion !== requestVersion) return;  // Ignore reset, changed mode, or switched experiments.
      state.result = result; renderStage(); scheduleNext(); refresh();
    } catch (error) { $('simVerdict').textContent = 'ENGINE ERROR'; alert(error.message); }
    finally { state.busy = false; $('runAttack').disabled = false; }
  });
  $('pauseAttack').addEventListener('click', () => {
    if (!state.result || state.position >= state.result.stages.length) return;
    state.paused = !state.paused;
    theater.classList.toggle('is-paused', state.paused);
    $('pauseAttack').textContent = state.paused ? '▶ RESUME' : 'Ⅱ PAUSE';
    if (state.paused) stopPlayback(); else scheduleNext();
  });
  $('stepAttack').addEventListener('click', () => {
    if (!state.result) { alert('Press RUN EXPERIMENT before stepping through evidence.'); return; }
    state.paused = true; stopPlayback(); theater.classList.add('is-paused');
    $('pauseAttack').textContent = '▶ RESUME';
    state.position = Math.min(state.position + 1, state.result.stages.length);
    renderStage();
  });
  $('resetAttack').addEventListener('click', () => setAttack(state.attack));
  $('speedControl').addEventListener('change', () => { if (state.timer !== null) scheduleNext(); });

  $('messageText').addEventListener('input', () => {
    const text = $('messageText').value;
    $('characterCount').textContent = new TextEncoder().encode(text).length + ' / 4096 UTF-8 bytes';
  });
  $('messageForm').addEventListener('submit', async event => {
    event.preventDefault(); clearAlert();
    const sender = $('senderSelect').value, recipient = $('recipientSelect').value, text = $('messageText').value;
    const bodyBytes = new TextEncoder().encode(text).length;
    if (!text.trim() || bodyBytes > 4096) { alert('Message text must use 1 to 4096 UTF-8 bytes.'); return; }
    if (sender === recipient) { alert('Select two different approved agents.'); return; }
    const button = $('messageForm').querySelector('button[type=submit]'); button.disabled = true;
    try {
      const receipt = await api('/api/messages', {sender, recipient, text});
      const panel = $('messageReceipt'); panel.hidden = false;
      panel.textContent = `${receipt.status} / ${receipt.detail}\nSIGNED RECEIPT VERIFIED: ${receipt.verified_receipt}\nENCRYPTED PACKET SIZE: ${receipt.wire_bytes} bytes\nMESSAGE ID: ${receipt.id}`;
      $('messageText').value = ''; $('characterCount').textContent = '0 / 4096 UTF-8 bytes';
      state.activeMessageId = receipt.id;
      const simulateButton = element('button','receipt-attack-action','RUN ATTACK AGAINST THIS MESSAGE ↗');
      simulateButton.type='button'; simulateButton.addEventListener('click',()=>{$('attackExperimentStart').scrollIntoView({behavior:'smooth'});});
      panel.append(document.createElement('br'),simulateButton);
      await refresh(); $('inboxAgentSelect').value = recipient; await loadInbox();
    } catch (error) { alert(error.message); }
    finally { button.disabled = false; }
  });
  async function loadInbox() {
    const name = $('inboxAgentSelect').value;
    const inbox = $('inboxList'); clear(inbox);
    if (!name) { inbox.append(element('p', 'muted', 'No trusted recipients are available.')); return; }
    try {
      const data = await api('/api/inbox/' + encodeURIComponent(name));
      if ($('inboxAgentSelect').value !== name) return;
      if (!data.messages.length) { inbox.append(element('p', 'muted', 'No messages delivered to this agent yet.')); return; }
      data.messages.forEach(message => {
        const card = element('article', 'inbox-item');
        const header = element('header');
        header.append(element('span', '', 'FROM / ' + message.sender));
        header.append(element('span', '', new Date(message.created * 1000).toLocaleTimeString()));
        card.append(header, element('p', '', message.text));
        inbox.append(card);
      });
    } catch (error) { inbox.append(element('p', 'muted', error.message)); }
  }
  $('inboxAgentSelect').addEventListener('change', loadInbox);
  $('createAgentForm').addEventListener('submit', async event => {
    event.preventDefault(); clearAlert();
    const name = $('newAgentName').value.trim();
    const button = $('createAgentForm').querySelector('button'); button.disabled = true;
    try {
      await api('/api/agents', {name});
      $('newAgentName').value = '';
      await refresh();
    } catch (error) { alert(error.message); }
    finally { button.disabled = false; }
  });
  function auditKeyLabel(key) { return key.replaceAll('_',' ').replace(/\b\w/g, c => c.toUpperCase()); }
  function auditValue(key, value) {
    const box=element('div','audit-field');
    box.append(element('span','audit-field-label',auditKeyLabel(key)));
    if (value !== null && typeof value === 'object') {
      box.append(element('pre','audit-field-value',JSON.stringify(value,null,2)));
    } else {
      box.append(element('pre','audit-field-value',value === null ? 'Not available' : String(value)));
    }
    return box;
  }
  function renderAuditDetail(entry) {
    const pane=$('auditDetails'); clear(pane);
    if (!entry) {pane.append(element('p','muted','No matching records. Send a message or run an experiment first.')); return;}
    const title=element('div','audit-inspect-title');
    title.append(element('span','audit-type-chip ' + entry.kind,entry.kind.toUpperCase()));
    title.append(element('h3','',entry.title));
    title.append(element('p','',entry.summary));
    pane.append(title);
    const identity=element('div','audit-identity-grid');
    for (const [key,value] of Object.entries({Audit_ID:entry.id,Message_ID:entry.message_id||'isolated test',Sender:entry.sender,Recipient:entry.recipient,Timestamp:entry.timestamp,Result:entry.status})) {
      identity.append(auditValue(key,value));
    }
    pane.append(identity);
    pane.append(element('h4','audit-heading','Security Operation Timeline'));
    const timeline=element('ol','audit-operation-steps');
    for (const [i,step] of (entry.steps||[]).entries()) {
      const li=element('li','audit-operation ' + (step.status||''));
      li.append(element('span','audit-operation-index',String(i+1).padStart(2,'0')));
      const text=element('div','');text.append(element('strong','',step.operation),element('small','',`${step.actor} / ${step.status}`),element('p','',step.detail));
      li.append(text);timeline.append(li);
    }
    pane.append(timeline,element('h4','audit-heading','Cryptographic Evidence / Defense Checks'));
    const fields=element('div','audit-evidence-fields');
    for (const [key,value] of Object.entries(entry.details||{})) fields.append(auditValue(key,value));
    if (Object.hasOwn(entry,'plaintext')) fields.append(auditValue('Opt-in local message plaintext',entry.plaintext));
    pane.append(fields,element('p','audit-privacy-caption',entry.privacy_note||'No private keys or derived symmetric keys recorded.'));
  }
  function renderAudit() {
    const query=$('auditSearch').value.toLowerCase().trim(), filter=$('auditFilter').value;
    const shown=state.audit.filter(e => (filter==='all'||e.kind===filter) && (!query||[e.message_id,e.sender,e.recipient,e.status,e.title,e.summary,e.id,JSON.stringify(e.details||{})].join(' ').toLowerCase().includes(query)));
    $('auditListCount').textContent=shown.length+' SHOWN';
    const list=$('auditEntries');clear(list);
    if (!shown.length) list.append(element('p','muted','No security events match your selection.'));
    for (const entry of shown) {
      const row=element('button','audit-entry ' + (entry.id===state.auditSelectedId?'selected':''));
      row.type='button';row.setAttribute('role','listitem');
      row.append(element('small','',entry.kind.toUpperCase()+' / '+entry.timestamp));
      row.append(element('strong','',entry.title));
      row.append(element('span','',`${entry.sender} → ${entry.recipient} / ${entry.status}`));
      row.append(element('span','audit-entry-id',entry.message_id ? entry.message_id.slice(0,18) : 'ISOLATED TEST'));
      row.addEventListener('click',()=>{state.auditSelectedId=entry.id;renderAudit();});
      list.append(row);
    }
    if (!shown.some(e=>e.id===state.auditSelectedId)) state.auditSelectedId=shown[0]?.id||null;
    // selected marker when selection changes due to filtering
    for (const [i,node] of Array.from(list.querySelectorAll('button')).entries()) node.classList.toggle('selected',shown[i].id===state.auditSelectedId);
    renderAuditDetail(shown.find(e=>e.id===state.auditSelectedId));
  }
  async function refreshAudit() {
    try {
      const optin=$('auditPlaintext').checked;
      const response=await api('/api/audit'+(optin?'?include_plaintext=1':''));
      state.audit=response.entries;
      $('auditTotal').textContent=response.total_count;
      $('auditMessages').textContent=response.counts_by_kind.message;
      $('auditAttacks').textContent=response.counts_by_kind.attack;
      renderAudit();
    } catch(error){alert(error.message);}
  }
  $('auditSearch').addEventListener('input',renderAudit);
  $('auditFilter').addEventListener('change',renderAudit);
  $('auditPlaintext').addEventListener('change',refreshAudit);
  $('auditRefresh').addEventListener('click',refreshAudit);
  function downloadAudit(filename,body,mime) {
    const blob=new Blob([body],{type:mime});const url=URL.createObjectURL(blob);
    const link=document.createElement('a');link.href=url;link.download=filename;
    document.body.append(link);link.click();link.remove();URL.revokeObjectURL(url);
  }
  async function exportAudit(format) {
    try {
      // The export is complete metadata history; plaintext stays excluded,
      // regardless of the inspector's explicitly enabled local disclosure.
      const data=await api('/api/audit?all=1');
      const records=data.entries;
      if(format==='json') return downloadAudit('multi_agent_security_audit.json',JSON.stringify({exported_at:new Date().toISOString(),retention:data.retention,entries:records},null,2),'application/json');
      const headers=['audit_id','kind','message_id','sender','recipient','timestamp','status','title','summary','details_json','steps_json'];
      const escapeCell=value=>{
        let raw=typeof value==='object'?JSON.stringify(value):String(value??'');
        if (/^[=+@-]/.test(raw)) raw="'"+raw;
        return '"'+raw.replaceAll('"','""')+'"';
      };
      const lines=[headers.join(','),...records.map(e=>[e.id,e.kind,e.message_id,e.sender,e.recipient,e.timestamp,e.status,e.title,e.summary,e.details,e.steps].map(escapeCell).join(','))];
      downloadAudit('multi_agent_security_audit.csv',lines.join('\r\n'),'text/csv;charset=utf-8');
    }catch(error){alert(error.message);}
  }
  $('auditExportJson').addEventListener('click',()=>exportAudit('json'));
  $('auditExportCsv').addEventListener('click',()=>exportAudit('csv'));

  $('refreshState').addEventListener('click', refresh);

  function addChat(who, text) {
    const chat = element('div', 'chat-bubble ' + (who === 'YOU' ? 'user' : 'system'));
    chat.append(element('small', '', who + ' / ' + new Date().toLocaleTimeString()));
    chat.append(element('p', '', text));
    $('chatHistory').append(chat); $('chatHistory').scrollTop = $('chatHistory').scrollHeight;
  }
  async function ask(question) {
    if (!question.trim()) return;
    clearAlert(); addChat('YOU', question);
    try { const answer = await api('/api/assistant', {question}); addChat('PROTOCOL ASSISTANT', answer.answer); }
    catch (error) { addChat('PROTOCOL ASSISTANT', 'Unable to reach the local explanation engine. ' + error.message); }
  }
  $('assistantForm').addEventListener('submit', event => {
    event.preventDefault(); const question = $('assistantQuestion').value;
    $('assistantQuestion').value = ''; ask(question);
  });
  qa('[data-question]').forEach(button => button.addEventListener('click', () => { page('assistant'); ask(button.dataset.question); }));
  setAttack('tamper');
  refresh();
  window.setInterval(() => { if (state.page === 'overview' || state.page === 'analytics' || state.page === 'simulator') refresh(); }, 10000);
})();
