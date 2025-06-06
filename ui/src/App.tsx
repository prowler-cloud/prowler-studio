import {RequestDetails} from 'deep-chat/dist/types/interceptors';
import {DeepChat} from 'deep-chat-react';
import './App.css';
import hljs from "highlight.js";
import React from 'react';

declare global {
  interface Window {
    hljs: typeof hljs;
  }
}

function App() {
  const baseApiUrl: string = process.env.BASE_API_URL || 'http://localhost';
  const apiPort: string = process.env.API_PORT || '8000';

  React.useEffect(() => {
    if (!window.hljs) {
      window.hljs = hljs;
    }
  }, []);

  return (
    <div className="App">
      <h1>Prowler Studio</h1>
      <p>DISCLAIMER: This chat has no memory and does not store any data. It is a simple chat interface to request new checks to Prowler Studio, so don't try to reference previous messages.</p>
      <div className="components">
        <DeepChat
          style={{borderRadius: '10px', width: '96vw', height: 'calc(95vh - 100px)', paddingTop: '10px'}}
          messageStyles={{default:{shared:{innerContainer:{fontSize: '1rem' }}}}}
          inputAreaStyle={{fontSize: '1rem'}}
          introMessage={{text: 'Request any new check to Prowler Studio by typing in the chat box below.'}}
          connect={{
            url: baseApiUrl + ':' + apiPort + '/new-check',
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            }
          }}
          requestBodyLimits={{ maxMessages: -1 }}
          requestInterceptor={(details: RequestDetails) => {
            const latestMessage = details.body.messages[details.body.messages.length - 1].text;
            details.body = {
              "user_query": latestMessage,
              "llm_provider": "openai",
              "llm_reference": "gpt-4o-mini"
            };
            return details;
          }}
          responseInterceptor={(response: any) => {
            return {
              text: response.user_answer
            }
          }}
        />
      </div>
    </div>
  );
}

export default App;
