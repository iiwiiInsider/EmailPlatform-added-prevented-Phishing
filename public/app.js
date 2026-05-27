const state = {
  sessionId: '',
  linkedEmail: ''
};

const linkForm = document.getElementById('linkForm');
const composeForm = document.getElementById('composeForm');
const inboxList = document.getElementById('inboxList');
const viewerBody = document.getElementById('viewerBody');
const viewerMeta = document.getElementById('viewerMeta');
const sessionState = document.getElementById('sessionState');
const riskBadge = document.getElementById('riskBadge');
const composeRisk = document.getElementById('composeRisk');
const inlineEditor = document.getElementById('inlineEditor');

function setRisk(el, analysis) {
  if (!analysis) {
    el.className = 'risk';
    el.textContent = '';
    return;
  }
  el.className = `risk ${analysis.riskLevel}`;
  const details = analysis.warnings?.length ? ` | ${analysis.warnings.join(' ')}` : '';
  el.textContent = `Risk: ${analysis.riskLevel.toUpperCase()} (score ${analysis.score})${details}`;
}

function sessionHeaders() {
  return state.sessionId ? { 'x-session-id': state.sessionId } : {};
}

async function linkAccount(formData) {
  const payload = {
    email: formData.get('email'),
    password: formData.get('password'),
    smtpHost: formData.get('smtpHost'),
    imapHost: formData.get('imapHost'),
    smtpPort: Number(formData.get('smtpPort')),
    imapPort: Number(formData.get('imapPort'))
  };

  const res = await fetch('/api/account/link', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Account linking failed');
  state.sessionId = data.sessionId;
  state.linkedEmail = data.email;
  sessionState.textContent = `Linked: ${data.email}`;
}

async function loadInbox() {
  if (!state.sessionId) return;
  const res = await fetch('/api/messages?limit=25', { headers: sessionHeaders() });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to load inbox');

  inboxList.innerHTML = '';
  for (const msg of data.messages) {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${msg.subject || '(No subject)'}</strong><br><small>${msg.from || ''}</small><br><small>${new Date(msg.date).toLocaleString()}</small>`;
    li.addEventListener('click', () => viewMessage(msg.uid));
    inboxList.appendChild(li);
  }
}

async function viewMessage(uid) {
  const res = await fetch(`/api/messages/${uid}`, { headers: sessionHeaders() });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to load message');

  const { message } = data;
  viewerMeta.textContent = `From: ${message.from} | To: ${message.to} | Subject: ${message.subject}`;
  viewerBody.innerHTML = message.html || `<pre>${message.text || ''}</pre>`;
  setRisk(riskBadge, message.analysis);
}

async function analyzeCompose(subject, text, html) {
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ from: state.linkedEmail, subject, text, html })
  });
  const data = await res.json();
  if (!res.ok) return;
  setRisk(composeRisk, data.analysis);
}

linkForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const fd = new FormData(linkForm);
    await linkAccount(fd);
    await loadInbox();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById('refreshBtn').addEventListener('click', async () => {
  try {
    await loadInbox();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById('newBtn').addEventListener('click', () => {
  document.getElementById('composePanel').scrollIntoView({ behavior: 'smooth' });
});

inlineEditor.addEventListener('input', () => {
  const subject = composeForm.subject.value || '';
  const text = composeForm.text.value || '';
  analyzeCompose(subject, text, inlineEditor.innerHTML);
});

composeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!state.sessionId) {
    alert('Please link an account first.');
    return;
  }

  const payload = {
    to: composeForm.to.value,
    cc: composeForm.cc.value,
    bcc: composeForm.bcc.value,
    subject: composeForm.subject.value,
    text: composeForm.text.value,
    html: inlineEditor.innerHTML
  };

  try {
    const res = await fetch('/api/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...sessionHeaders() },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.error || 'Send failed');
    }
    setRisk(composeRisk, data.analysis);
    alert('Email sent.');
    composeForm.reset();
    inlineEditor.innerHTML = '';
    await loadInbox();
  } catch (error) {
    alert(error.message);
  }
});
