// Same-origin fetch with the session cookie; returns the status and body text to the Blazor circuit.
export async function request(path, method, bodyJson) {
  try {
    const response = await fetch(path, {
      method,
      credentials: 'include',
      headers: bodyJson ? { 'content-type': 'application/json', accept: 'application/json' } : { accept: 'application/json' },
      body: bodyJson ?? undefined,
    });
    return { status: response.status, text: await response.text() };
  } catch (error) {
    return { status: 0, text: JSON.stringify({ message: 'Could not reach the server. Check your connection and try again.' }) };
  }
}

// Puts text on the clipboard (the invitation link). Returns false when the browser refuses.
export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
}

// Uploads the files chosen in <input type="file"> elements (by id) as multipart form data, with the session cookie. fields: [{ name, inputId }].
export async function upload(path, fields) {
  try {
    const form = new FormData();
    for (const field of fields) {
      const file = document.getElementById(field.inputId)?.files?.[0];
      if (file) form.append(field.name, file, file.name);
    }
    const response = await fetch(path, { method: 'POST', credentials: 'include', headers: { accept: 'application/json' }, body: form });
    return { status: response.status, text: await response.text() };
  } catch (error) {
    return { status: 0, text: JSON.stringify({ message: 'Could not reach the server. Check your connection and try again.' }) };
  }
}
