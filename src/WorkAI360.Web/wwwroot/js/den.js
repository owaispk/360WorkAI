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
