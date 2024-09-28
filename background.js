chrome.webRequest.onBeforeRequest.addListener(
    function (details) {
        chrome.tabs.sendMessage(details.tabId, { 
            action: "checkDownloadPermission", 
            url: details.url 
        });
        return { cancel: true };
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
);

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.action === "allowDownload") {
        chrome.downloads.download({ url: message.url });
    } else if (message.action === "showPopup") {
        // Open the extension's popup
        chrome.action.openPopup();
    }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete') {
        // Execute content script to scrape URL and send message
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            files: ['content.js']
        }).then(() => {
            // Send a message to content script to start scraping
            chrome.tabs.sendMessage(tabId, { action: "scrape" });
        });

        // Open the popup after the URL has been scraped
        chrome.action.openPopup();
    }
});
