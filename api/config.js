module.exports = (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=UTF-8');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    
    const configData = {
        status: 'success',
        supabaseUrl: process.env.SUPABASE_URL || '',
        supabaseAnonKey: process.env.SUPABASE_ANON_KEY || '',
        projectId: process.env.SUPABASE_PROJECT_ID || ''
    };

    if (typeof res.status === 'function') {
        res.status(200).json(configData);
    } else {
        res.writeHead(200);
        res.end(JSON.stringify(configData));
    }
};
