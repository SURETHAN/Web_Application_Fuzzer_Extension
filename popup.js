document.addEventListener('DOMContentLoaded', async function () {
    let progress = 0;
    const progressBar = document.getElementById('progress-bar');
    const statusText = document.getElementById('status');
    const cancelButton = document.getElementById('cancel-button');
    const downloadFileList = document.getElementById('downloaded-file-list');

    if (!progressBar || !statusText || !cancelButton || !downloadFileList) {
        console.error('One or more elements are missing from the DOM.');
        return;
    }

    function updateProgressBar(percentage) {
        progressBar.style.width = percentage + '%';
    }

    function handleFilePermission(fileUrl, callback) {
        fetch('http://127.0.0.1:5000/check_file_download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_url: fileUrl })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'unwanted') {
                const userConfirmed = confirm(`The file ${fileUrl} is identified as unwanted. Do you want to allow this download?`);
                if (userConfirmed) {
                    callback();
                }
            } else {
                callback();
            }
        })
        .catch(error => {
            console.error('Error checking file:', error);
            callback(); 
        });
    }

    function addDownloadedFile(fileUrl) {
        fetch('http://127.0.0.1:5000/add_downloaded_file', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_url: fileUrl })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const listItem = document.createElement('li');
                listItem.textContent = fileUrl;
                downloadFileList.appendChild(listItem);
            } else {
                console.error('Failed to add downloaded file.');
            }
        })
        .catch(error => {
            console.error('Error adding downloaded file:', error);
        });
    }

    async function generateReport(url) {
        try {
            const response = await fetch('http://127.0.0.1:5000/generate_report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            updateProgressBar(50); 

            if (response.ok) {
                const blob = await response.blob();
                const fileUrl = URL.createObjectURL(blob);
                
                handleFilePermission(fileUrl, () => {
                    const link = document.createElement('a');
                    link.href = fileUrl;
                    link.download = 'security_report.pdf';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    updateProgressBar(100); 
                    statusText.textContent = 'Report downloaded successfully.';
                    addDownloadedFile(fileUrl);
                });
            } else {
                statusText.textContent = 'Failed to generate report.';
                updateProgressBar(0); 
            }
        } catch (error) {
            statusText.textContent = 'An error occurred: ' + error.message;
            updateProgressBar(0); 
        }
    }

    function monitorWebpage() {
        chrome.tabs.query({ active: true, currentWindow: true }, async function (tabs) {
            const currentTab = tabs[0];
            const url = currentTab.url;

            if (!url) {
                statusText.textContent = 'Failed to get the current URL.';
                return;
            }

            statusText.textContent = `Parsing: ${url}`;
            updateProgressBar(10); 

            await generateReport(url);
        });
    }
    monitorWebpage();
    cancelButton.addEventListener('click', () => {
        statusText.textContent = 'Report generation cancelled.';
        updateProgressBar(0);
        cancelButton.style.display = 'none';
    });
});
