// File: api.js (or similar)
import axios from 'axios';

const apiClient = axios.create({ baseURL: '/api' });

apiClient.interceptors.response.use(
  (response) => response, // Pass through successful responses
  (error) => {
    // Check if we have a response and data from the server
    if (error.response && error.response.data) {
      const { data } = error.response;

      // Check for our specific IAP expiration code
      if (error.response.status === 401 && data.error_code === 'IAP_TOKEN_EXPIRED' && data.renewal_url) {
        
        console.warn('IAP token expired, redirecting for renewal...');
        
        // Get the renewal URL from the API response
        const renewalBaseUrl = data.renewal_url;
        
        // Get the current page URL to be used as the redirect parameter
        const redirectAfterRenewal = window.location.href;
        
        // Construct the final URL
        const finalUrl = `${renewalBaseUrl}?redirect=${encodeURIComponent(redirectAfterRenewal)}`;

        // Perform a full-page redirect to the Nginx proxy
        window.location.href = finalUrl;
        
        // Stop the failed API call from propagating
        return new Promise(() => {});
      }
    }

    // For all other errors, just re-throw
    return Promise.reject(error);
  }
);

export default apiClient;