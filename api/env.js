module.exports = (req, res) => {
    const clientConfig = {
        url: process.env.SUPABASE_URL || '',
        key: process.env.SUPABASE_ANON_KEY || '',
        projectId: process.env.SUPABASE_PROJECT_ID || ''
    };
    const js = `window.SUPABASE_CONFIG = ${JSON.stringify(clientConfig)};`;
    
    res.setHeader('Content-Type', 'text/javascript; charset=UTF-8');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    
    if (typeof res.status === 'function') {
        res.status(200).send(js);
    } else {
        res.writeHead(200);
        res.end(js);
    }
};
