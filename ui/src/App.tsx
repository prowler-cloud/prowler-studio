import {RequestDetails} from 'deep-chat/dist/types/interceptors';
import {DeepChat} from 'deep-chat-react';
import './App.css';

function App() {
  const baseApiUrl: string = process.env.BASE_API_URL || 'http://localhost:4501';

  console.log('baseApiUrl:', baseApiUrl);

  return (
    <div className="App">
      <h1>Prowler Studio</h1>
      <p>DISCLAIMER: This chat has no memory and does not store any data. It is a simple chat interface to request new checks to Prowler Studio, so don't try to reference previous messages.</p>
      <div className="components">
        <DeepChat
          style={{borderRadius: '10px', width: '96vw', height: 'calc(100vh - 100px)', paddingTop: '10px'}}
          messageStyles={{default: {shared: {innerContainer: {fontSize: '1rem'}}}}}
          inputAreaStyle={{fontSize: '1rem'}}
          introMessage={{text: 'Request any new check to Prowler Studio by typing in the chat box below.'}}
          connect={{
            url: baseApiUrl + '/deployments/ChecKreationWorkflow/tasks/run',
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            }
          }}
          requestBodyLimits={{maxMessages: -1}}
          requestInterceptor={(details: RequestDetails) => {
            return details;
          }}
          responseInterceptor={(response: any) => {
            return response;
          }}
        />
      </div>
    </div>
  );
}

export default App;
