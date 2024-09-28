chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "scrape") {
    
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const currentTab = tabs[0];
      const currentUrl = currentTab.url; 

      
      sendResponse({ url: currentUrl });
    });

  } else if (request.action === "checkDownloadPermission") {
    
    const userConfirmed = confirm(`The site is trying to download a file: ${request.url}. Do you want to allow this download?`);

    if (userConfirmed) {
      
      chrome.runtime.sendMessage({ action: "allowDownload", url: request.url });
    } else {
      console.log("Download blocked by user.");
    }
  }

  
  return true;
});


window.addEventListener('load', () => {
  
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const currentTab = tabs[0];
    const currentUrl = currentTab.url;
    chrome.runtime.sendMessage({ 
      action: "scrapedURL", 
      url: currentUrl 
    });
  });
});
