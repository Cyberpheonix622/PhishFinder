import { useState } from 'react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://127.0.0.1:5000/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setResult(data.result);
    } catch (error) {
      console.error('Error:', error);
      setResult('Something went wrong.');
    }
  };

  return (
    <div className="App" style={{ padding: 30 }}>
      <h1>🔎 Phishing Link Checker</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Enter URL..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{ padding: 10, width: '300px', marginRight: 10 }}
        />
        <button type="submit" style={{ padding: 10 }}>Check</button>
      </form>
      {result && <h2 style={{ marginTop: 20 }}>{result}</h2>}
    </div>
  );
}

export default App;