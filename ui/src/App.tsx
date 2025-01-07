import {RequestDetails} from 'deep-chat/dist/types/interceptors';
import {DeepChat} from 'deep-chat-react';
import './App.css';

function App() {
  return (
    <div className="App">
      <h1>Prowler Studio</h1>
      <div className="components">
        <DeepChat
          style={{borderRadius: '10px', width: '96vw', height: 'calc(100vh - 100px)', paddingTop: '10px'}}
          messageStyles={{default: {shared: {innerContainer: {fontSize: '1rem'}}}}}
          inputAreaStyle={{fontSize: '1rem'}}
          introMessage={{text: 'Request any new check to Prowler Studio by typing in the chat box below.'}}
          connect={{url: 'http://localhost:4501/deployments/ChecKreationWorkflow/tasks/run', method: 'POST', headers: {'Content-Type': 'application/json'}, additionalBodyProps: {user_query: 'Hello!', model_provider: 'gemini', model_reference: 'Flash 1.5', api_key: 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX'}}}
          requestBodyLimits={{maxMessages: 1}}
          requestInterceptor={(details: RequestDetails) => {
            console.log(details);
            return details;
          }}
          responseInterceptor={(response: any) => {
            console.log(response);
            return response;
          }}
        />
      </div>
    </div>
  );
}

export default App;
