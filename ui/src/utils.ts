export function parseCheckResponse(message: string): { text: string, isCheck: boolean } {
    try {
        const apiCheckMessageRegex = /(.*?)('tests':\s*'.*?')(.*?)('code':\s*'.*?'.*)/;
        const match = message.match(apiCheckMessageRegex);

        if (match) {
            const metadata = match[1].trim();
            const tests = match[2].trim();
            const code = match[4].trim();

            let formattedMetadata = metadata.replace(/'/g, '"') // Replace all single quotes with double quotes

            // Replace last , with }
            const lastCommaIndex = formattedMetadata.lastIndexOf(',');

            if (lastCommaIndex !== -1) {
                formattedMetadata = formattedMetadata.substring(0, lastCommaIndex) + '}';
            }

            const metadataObj = JSON.parse(formattedMetadata);
            const metadataContent = JSON.stringify(metadataObj.metadata, null, 2);
            const metadataContentText = '```json\n' + metadataContent + '\n```';

            let formattedTests = tests.replace(/'/g, '"'); // Replace all single quotes with double quotes

            // Split the string in two parts, the first part is the key and the second part is the value use the first : as reference

            const firstColonIndex = formattedTests.indexOf(':');

            if (firstColonIndex !== -1) {
                formattedTests = formattedTests.substring(firstColonIndex + 1).trim();
            }

            // Remove first and last double quotes
            formattedTests = formattedTests.substring(1, formattedTests.length - 1);

            // Replace escaped new lines with actual new lines
            formattedTests = formattedTests.replace(/\\n/g, '\n');

            // Do the same for code

            let formattedCode = code.replace(/'/g, '"'); // Replace all single quotes with double quotes

            // Split the string in two parts, the first part is the key and the second part is the value use the first : as reference

            const firstColonIndexCode = formattedCode.indexOf(':');

            if (firstColonIndexCode !== -1) {
                formattedCode = formattedCode.substring(firstColonIndexCode + 1).trim();
            }

            // Remove first and last double quotes
            formattedCode = formattedCode.substring(1, formattedCode.length - 2);

            // Replace escaped new lines with actual new lines
            formattedCode = formattedCode.replace(/\\n/g, '\n');

            // Console log the formatted metadata, code and tests
            console.log('Metadata:', metadataContentText);
            console.log('Code:', formattedCode);
            console.log('Tests:', formattedTests);

            return {
                text: `Here you can find the metadata, code and unit testing for the requested check:\nMetadata:\n${metadataContentText}\n\nCode:\n\n${formattedCode}\n\n\nTests:\n\n${formattedTests}\n`,
                isCheck: true,
            };
        } else {
            return {
                text: message,
                isCheck: false,
            };
        }
    } catch (error) {
        console.error('Error parsing check response:', error);
        return {
            text: message,
            isCheck: false,
        };
    }
}
