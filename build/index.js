#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ErrorCode, ListToolsRequestSchema, McpError, } from '@modelcontextprotocol/sdk/types.js';
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import open from 'open';
import http from 'http';
import { URL } from 'url';
class LocalYouTubeMCPServer {
    server;
    oauth2Client;
    youtube;
    isAuthenticated = false;
    tokensPath;
    constructor() {
        // Store tokens in user's home directory
        this.tokensPath = path.join(os.homedir(), '.youtube-mcp-tokens.json');
        // Initialize server with capabilities first
        this.server = new Server({
            name: 'youtube-mcp-server',
            version: '1.0.0',
        }, {
            capabilities: {
                tools: {},
            },
        });
        this.setupAuth();
        this.setupToolHandlers();
    }
    setupAuth() {
        // Use environment variables or default OAuth client for installed apps
        const clientId = process.env.YOUTUBE_CLIENT_ID || '1087470582103-example.apps.googleusercontent.com';
        const clientSecret = process.env.YOUTUBE_CLIENT_SECRET || 'GOCSPX-example';
        const redirectUri = 'http://localhost:8080';
        this.oauth2Client = new OAuth2Client(clientId, clientSecret, redirectUri);
        this.youtube = google.youtube({ version: 'v3', auth: this.oauth2Client });
    }
    async loadStoredTokens() {
        try {
            const tokensData = await fs.readFile(this.tokensPath, 'utf8');
            return JSON.parse(tokensData);
        }
        catch (error) {
            return null;
        }
    }
    async saveTokens(tokens) {
        try {
            await fs.writeFile(this.tokensPath, JSON.stringify(tokens, null, 2));
            console.error(`Tokens saved to: ${this.tokensPath}`);
        }
        catch (error) {
            console.error('Error saving tokens:', error);
        }
    }
    async checkAuthentication() {
        if (this.isAuthenticated) {
            return true;
        }
        const tokens = await this.loadStoredTokens();
        if (!tokens?.refresh_token) {
            return false;
        }
        try {
            this.oauth2Client.setCredentials(tokens);
            // Test the connection by getting channel info
            const response = await this.youtube.channels.list({
                part: ['snippet'],
                mine: true,
            });
            if (response.data.items && response.data.items.length > 0) {
                this.isAuthenticated = true;
                console.error(`Authenticated as: ${response.data.items[0].snippet.title}`);
                return true;
            }
            return false;
        }
        catch (error) {
            console.error('Authentication test failed:', error.message);
            // Try to refresh the token
            try {
                const { credentials } = await this.oauth2Client.refreshAccessToken();
                const userTokens = {
                    access_token: credentials.access_token || undefined,
                    refresh_token: credentials.refresh_token || undefined,
                    token_type: credentials.token_type || undefined,
                    expiry_date: credentials.expiry_date || undefined,
                    scope: credentials.scope || undefined,
                };
                await this.saveTokens(userTokens);
                this.oauth2Client.setCredentials(credentials);
                this.isAuthenticated = true;
                return true;
            }
            catch (refreshError) {
                console.error('Token refresh failed:', refreshError.message);
                return false;
            }
        }
    }
    async initiateUserAuth() {
        const scopes = [
            'https://www.googleapis.com/auth/youtube.readonly',
            'https://www.googleapis.com/auth/youtube',
            'https://www.googleapis.com/auth/youtube.force-ssl',
            'https://www.googleapis.com/auth/youtubepartner',
            'https://www.googleapis.com/auth/youtube.upload'
        ];
        const authUrl = this.oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: scopes,
            prompt: 'consent'
        });
        return authUrl;
    }
    async startCallbackServer() {
        return new Promise((resolve, reject) => {
            const server = http.createServer((req, res) => {
                if (req.url) {
                    const url = new URL(req.url, 'http://localhost:8080');
                    const code = url.searchParams.get('code');
                    const error = url.searchParams.get('error');
                    if (error) {
                        res.writeHead(400, { 'Content-Type': 'text/html' });
                        res.end('<h1>Authentication Failed</h1><p>Permission was denied or an error occurred.</p>');
                        server.close();
                        reject(new Error(`OAuth error: ${error}`));
                        return;
                    }
                    if (code) {
                        res.writeHead(200, { 'Content-Type': 'text/html' });
                        res.end(`
                            <html>
                                <body>
                                    <h1>✅ Authentication Successful!</h1>
                                    <p>You can close this window. YouTube access has been granted.</p>
                                    <script>
                                        setTimeout(() => window.close(), 2000);
                                    </script>
                                </body>
                            </html>
                        `);
                        server.close();
                        resolve(code);
                        return;
                    }
                }
                res.writeHead(404, { 'Content-Type': 'text/html' });
                res.end('<h1>Not Found</h1>');
            });
            server.listen(8080, 'localhost', () => {
                console.error('OAuth callback server started on http://localhost:8080');
            });
            server.on('error', (err) => {
                reject(err);
            });
            // Timeout after 5 minutes
            setTimeout(() => {
                server.close();
                reject(new Error('OAuth flow timed out'));
            }, 5 * 60 * 1000);
        });
    }
    async completeAuth(code) {
        try {
            const { tokens } = await this.oauth2Client.getToken(code);
            const userTokens = {
                access_token: tokens.access_token || undefined,
                refresh_token: tokens.refresh_token || undefined,
                token_type: tokens.token_type || undefined,
                expiry_date: tokens.expiry_date || undefined,
                scope: tokens.scope || undefined,
            };
            await this.saveTokens(userTokens);
            this.oauth2Client.setCredentials(tokens);
            this.isAuthenticated = true;
            // Get channel info to confirm
            const response = await this.youtube.channels.list({
                part: ['snippet', 'statistics'],
                mine: true,
            });
            if (response.data.items && response.data.items.length > 0) {
                const channel = response.data.items[0];
                console.error(`Successfully authenticated as: ${channel.snippet.title}`);
            }
            return true;
        }
        catch (error) {
            console.error('Error during authentication:', error);
            return false;
        }
    }
    setupToolHandlers() {
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            return {
                tools: [
                    {
                        name: 'youtube_authenticate',
                        description: 'Start YouTube authentication process or check status',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                auth_code: {
                                    type: 'string',
                                    description: 'Authorization code from Google (if completing auth)',
                                },
                                force_reauth: {
                                    type: 'boolean',
                                    description: 'Force re-authentication even if already authenticated',
                                    default: false,
                                },
                            },
                        },
                    },
                    {
                        name: 'youtube_status',
                        description: 'Check YouTube connection status and account info',
                        inputSchema: {
                            type: 'object',
                            properties: {},
                        },
                    },
                    {
                        name: 'youtube_search_videos',
                        description: 'Search for YouTube videos with various filters',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                query: {
                                    type: 'string',
                                    description: 'Search query',
                                },
                                max_results: {
                                    type: 'number',
                                    description: 'Maximum videos to return (1-50)',
                                    default: 25,
                                    minimum: 1,
                                    maximum: 50,
                                },
                                order: {
                                    type: 'string',
                                    enum: ['relevance', 'date', 'rating', 'viewCount', 'title'],
                                    description: 'Order of results',
                                    default: 'relevance',
                                },
                                published_after: {
                                    type: 'string',
                                    description: 'ISO 8601 date - only videos published after this date',
                                },
                                published_before: {
                                    type: 'string',
                                    description: 'ISO 8601 date - only videos published before this date',
                                },
                                duration: {
                                    type: 'string',
                                    enum: ['any', 'short', 'medium', 'long'],
                                    description: 'Video duration filter',
                                    default: 'any',
                                },
                            },
                            required: ['query'],
                        },
                    },
                    {
                        name: 'youtube_get_video',
                        description: 'Get detailed information about a specific video',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                video_id: {
                                    type: 'string',
                                    description: 'YouTube video ID',
                                },
                                include_comments: {
                                    type: 'boolean',
                                    description: 'Include top comments in the response',
                                    default: false,
                                },
                            },
                            required: ['video_id'],
                        },
                    },
                    {
                        name: 'youtube_get_channel',
                        description: 'Get information about a YouTube channel',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                channel_id: {
                                    type: 'string',
                                    description: 'YouTube channel ID',
                                },
                                username: {
                                    type: 'string',
                                    description: 'YouTube username (alternative to channel_id)',
                                },
                                include_statistics: {
                                    type: 'boolean',
                                    description: 'Include channel statistics (subscribers, views, etc.)',
                                    default: true,
                                },
                            },
                        },
                    },
                    {
                        name: 'youtube_list_channel_videos',
                        description: 'List videos from a specific channel',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                channel_id: {
                                    type: 'string',
                                    description: 'YouTube channel ID',
                                },
                                max_results: {
                                    type: 'number',
                                    description: 'Maximum videos to return (1-50)',
                                    default: 25,
                                    minimum: 1,
                                    maximum: 50,
                                },
                                order: {
                                    type: 'string',
                                    enum: ['date', 'rating', 'relevance', 'title', 'viewCount'],
                                    description: 'Order of results',
                                    default: 'date',
                                },
                            },
                            required: ['channel_id'],
                        },
                    },
                    {
                        name: 'youtube_get_my_channel',
                        description: 'Get information about the authenticated user\'s own YouTube channel',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                include_analytics: {
                                    type: 'boolean',
                                    description: 'Include basic analytics data',
                                    default: false,
                                },
                            },
                        },
                    },
                    {
                        name: 'youtube_list_my_videos',
                        description: 'List videos from the authenticated user\'s channel',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                max_results: {
                                    type: 'number',
                                    description: 'Maximum videos to return (1-50)',
                                    default: 25,
                                    minimum: 1,
                                    maximum: 50,
                                },
                                order: {
                                    type: 'string',
                                    enum: ['date', 'rating', 'title', 'viewCount'],
                                    description: 'Order of results',
                                    default: 'date',
                                },
                            },
                        },
                    },
                    {
                        name: 'youtube_get_playlists',
                        description: 'Get playlists from a channel (authenticated user\'s channel if channel_id not provided)',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                channel_id: {
                                    type: 'string',
                                    description: 'YouTube channel ID (optional - uses authenticated user if not provided)',
                                },
                                max_results: {
                                    type: 'number',
                                    description: 'Maximum playlists to return (1-50)',
                                    default: 25,
                                    minimum: 1,
                                    maximum: 50,
                                },
                            },
                        },
                    },
                    {
                        name: 'youtube_get_playlist_videos',
                        description: 'Get videos from a specific playlist',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                playlist_id: {
                                    type: 'string',
                                    description: 'YouTube playlist ID',
                                },
                                max_results: {
                                    type: 'number',
                                    description: 'Maximum videos to return (1-50)',
                                    default: 25,
                                    minimum: 1,
                                    maximum: 50,
                                },
                            },
                            required: ['playlist_id'],
                        },
                    },
                    {
                        name: 'youtube_get_comments',
                        description: 'Get comments for a specific video',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                video_id: {
                                    type: 'string',
                                    description: 'YouTube video ID',
                                },
                                max_results: {
                                    type: 'number',
                                    description: 'Maximum comments to return (1-100)',
                                    default: 20,
                                    minimum: 1,
                                    maximum: 100,
                                },
                                order: {
                                    type: 'string',
                                    enum: ['time', 'relevance'],
                                    description: 'Order of comments',
                                    default: 'relevance',
                                },
                            },
                            required: ['video_id'],
                        },
                    },
                    {
                        name: 'youtube_get_trending',
                        description: 'Get trending videos for a specific region',
                        inputSchema: {
                            type: 'object',
                            properties: {
                                region_code: {
                                    type: 'string',
                                    description: 'ISO 3166-1 alpha-2 country code (e.g., US, GB, IN)',
                                    default: 'US',
                                },
                                category_id: {
                                    type: 'string',
                                    description: 'Category ID (e.g., 10 for Music, 20 for Gaming)',
                                    default: '0',
                                },
                                max_results: {
                                    type: 'number',
                                    description: 'Maximum videos to return (1-50)',
                                    default: 25,
                                    minimum: 1,
                                    maximum: 50,
                                },
                            },
                        },
                    },
                ],
            };
        });
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const { name, arguments: args } = request.params;
            try {
                switch (name) {
                    case 'youtube_authenticate':
                        return await this.handleAuthenticate(args);
                    case 'youtube_status':
                        return await this.handleStatus();
                    case 'youtube_search_videos':
                    case 'youtube_get_video':
                    case 'youtube_get_channel':
                    case 'youtube_list_channel_videos':
                    case 'youtube_get_my_channel':
                    case 'youtube_list_my_videos':
                    case 'youtube_get_playlists':
                    case 'youtube_get_playlist_videos':
                    case 'youtube_get_comments':
                    case 'youtube_get_trending':
                        // Check authentication for operations that need it
                        if (name.includes('my_') || name === 'youtube_get_my_channel' || name === 'youtube_list_my_videos') {
                            if (!(await this.checkAuthentication())) {
                                return {
                                    content: [
                                        {
                                            type: 'text',
                                            text: '❌ Not authenticated with YouTube. Please run youtube_authenticate first.',
                                        },
                                    ],
                                    isError: true,
                                };
                            }
                        }
                        return await this.handleYouTubeOperation(name, args);
                    default:
                        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
                }
            }
            catch (error) {
                console.error(`Error in ${name}:`, error);
                throw new McpError(ErrorCode.InternalError, `Error executing ${name}: ${error.message}`);
            }
        });
    }
    async handleAuthenticate(args) {
        const { auth_code, force_reauth = false } = args;
        // If we have an auth code, complete the authentication
        if (auth_code) {
            const success = await this.completeAuth(auth_code);
            if (success) {
                const response = await this.youtube.channels.list({
                    part: ['snippet', 'statistics'],
                    mine: true,
                });
                const channel = response.data.items[0];
                return {
                    content: [
                        {
                            type: 'text',
                            text: `✅ Successfully authenticated!\n\nChannel: ${channel.snippet.title}\nSubscribers: ${channel.statistics.subscriberCount || 'Hidden'}\nTotal videos: ${channel.statistics.videoCount || 'Unknown'}\n\nYou can now use all YouTube tools.`,
                        },
                    ],
                };
            }
            else {
                return {
                    content: [
                        {
                            type: 'text',
                            text: '❌ Authentication failed. Please check the authorization code and try again.',
                        },
                    ],
                    isError: true,
                };
            }
        }
        // Check if already authenticated (unless forced)
        if (!force_reauth && await this.checkAuthentication()) {
            const response = await this.youtube.channels.list({
                part: ['snippet', 'statistics'],
                mine: true,
            });
            const channel = response.data.items[0];
            return {
                content: [
                    {
                        type: 'text',
                        text: `✅ Already authenticated with YouTube!\n\nChannel: ${channel.snippet.title}\nSubscribers: ${channel.statistics.subscriberCount || 'Hidden'}\nTotal videos: ${channel.statistics.videoCount || 'Unknown'}`,
                    },
                ],
            };
        }
        // Start automatic authentication flow
        try {
            const authUrl = await this.initiateUserAuth();
            // Start the callback server
            const callbackPromise = this.startCallbackServer();
            // Open browser
            let browserMessage = '';
            try {
                await open(authUrl);
                browserMessage = '\n\n🌐 Browser opened automatically!';
            }
            catch (error) {
                browserMessage = '\n\n⚠️ Could not open browser automatically. Please visit the URL.';
            }
            // Wait for the OAuth callback
            try {
                const authCode = await callbackPromise;
                // Automatically complete authentication
                const success = await this.completeAuth(authCode);
                if (success) {
                    const response = await this.youtube.channels.list({
                        part: ['snippet', 'statistics'],
                        mine: true,
                    });
                    const channel = response.data.items[0];
                    return {
                        content: [
                            {
                                type: 'text',
                                text: `✅ **Authentication Completed Automatically!**\n\nChannel: ${channel.snippet.title}\nSubscribers: ${channel.statistics.subscriberCount || 'Hidden'}\nTotal videos: ${channel.statistics.videoCount || 'Unknown'}\n\nYouTube access is now ready!`,
                            },
                        ],
                    };
                }
                else {
                    return {
                        content: [
                            {
                                type: 'text',
                                text: '❌ Authentication failed during token exchange. Please try again.',
                            },
                        ],
                        isError: true,
                    };
                }
            }
            catch (callbackError) {
                return {
                    content: [
                        {
                            type: 'text',
                            text: `🔐 **YouTube Authentication in Progress**

Please visit this URL to authorize access: ${authUrl}${browserMessage}

**If automatic completion fails:**
1. Complete the authorization in your browser
2. Copy the authorization code that appears
3. Run: youtube_authenticate with the auth_code parameter

Waiting for authorization... (${callbackError.message})`,
                        },
                    ],
                };
            }
        }
        catch (error) {
            return {
                content: [
                    {
                        type: 'text',
                        text: `❌ Error during authentication setup: ${error.message}`,
                    },
                ],
                isError: true,
            };
        }
    }
    async handleStatus() {
        if (await this.checkAuthentication()) {
            try {
                const response = await this.youtube.channels.list({
                    part: ['snippet', 'statistics', 'contentDetails'],
                    mine: true,
                });
                const channel = response.data.items[0];
                return {
                    content: [
                        {
                            type: 'text',
                            text: `✅ **YouTube Connected**

📺 Channel: ${channel.snippet.title}
👥 Subscribers: ${channel.statistics.subscriberCount || 'Hidden'}
🎥 Total videos: ${channel.statistics.videoCount || 'Unknown'}
👁️ Total views: ${channel.statistics.viewCount || 'Unknown'}
🆔 Channel ID: ${channel.id}

🔧 Authentication file: ${this.tokensPath}`,
                        },
                    ],
                };
            }
            catch (error) {
                return {
                    content: [
                        {
                            type: 'text',
                            text: `⚠️ Connected but unable to fetch channel details: ${error.message}`,
                        },
                    ],
                };
            }
        }
        else {
            return {
                content: [
                    {
                        type: 'text',
                        text: '❌ **Not connected to YouTube**\n\nRun youtube_authenticate to get started.',
                    },
                ],
            };
        }
    }
    async handleYouTubeOperation(operation, args) {
        switch (operation) {
            case 'youtube_search_videos':
                return await this.searchVideos(args);
            case 'youtube_get_video':
                return await this.getVideo(args);
            case 'youtube_get_channel':
                return await this.getChannel(args);
            case 'youtube_list_channel_videos':
                return await this.listChannelVideos(args);
            case 'youtube_get_my_channel':
                return await this.getMyChannel(args);
            case 'youtube_list_my_videos':
                return await this.listMyVideos(args);
            case 'youtube_get_playlists':
                return await this.getPlaylists(args);
            case 'youtube_get_playlist_videos':
                return await this.getPlaylistVideos(args);
            case 'youtube_get_comments':
                return await this.getComments(args);
            case 'youtube_get_trending':
                return await this.getTrending(args);
            default:
                throw new Error(`Unknown operation: ${operation}`);
        }
    }
    // YouTube operation methods
    async searchVideos(args) {
        const { query, max_results = 25, order = 'relevance', published_after, published_before, duration = 'any' } = args;
        const searchParams = {
            part: ['snippet'],
            q: query,
            type: ['video'],
            maxResults: Math.min(max_results, 50),
            order: order,
        };
        if (published_after)
            searchParams.publishedAfter = published_after;
        if (published_before)
            searchParams.publishedBefore = published_before;
        if (duration !== 'any')
            searchParams.videoDuration = duration;
        const response = await this.youtube.search.list(searchParams);
        const videos = response.data.items || [];
        const videoIds = videos.map((v) => v.id.videoId).join(',');
        // Get additional details
        const detailsResponse = await this.youtube.videos.list({
            part: ['statistics', 'contentDetails'],
            id: videoIds,
        });
        const detailsMap = new Map(detailsResponse.data.items.map((item) => [item.id, item]));
        const enrichedVideos = videos.map((video) => {
            const details = detailsMap.get(video.id.videoId);
            return {
                id: video.id.videoId,
                title: video.snippet.title,
                channel: video.snippet.channelTitle,
                channelId: video.snippet.channelId,
                description: video.snippet.description,
                publishedAt: video.snippet.publishedAt,
                thumbnail: video.snippet.thumbnails.high?.url || video.snippet.thumbnails.default?.url,
                views: details?.statistics?.viewCount || 'N/A',
                likes: details?.statistics?.likeCount || 'N/A',
                comments: details?.statistics?.commentCount || 'N/A',
                duration: details?.contentDetails?.duration || 'N/A',
            };
        });
        return {
            content: [
                {
                    type: 'text',
                    text: `🔍 **YouTube Search Results**\n\nQuery: "${query}"\nFound: ${videos.length} videos\n\n${JSON.stringify(enrichedVideos, null, 2)}`,
                },
            ],
        };
    }
    async getVideo(args) {
        const { video_id, include_comments = false } = args;
        const response = await this.youtube.videos.list({
            part: ['snippet', 'statistics', 'contentDetails', 'status'],
            id: [video_id],
        });
        if (!response.data.items || response.data.items.length === 0) {
            return {
                content: [
                    {
                        type: 'text',
                        text: '❌ Video not found',
                    },
                ],
                isError: true,
            };
        }
        const video = response.data.items[0];
        let result = `🎥 **Video Details**\n\n${JSON.stringify(video, null, 2)}`;
        if (include_comments) {
            try {
                const commentsResponse = await this.youtube.commentThreads.list({
                    part: ['snippet'],
                    videoId: video_id,
                    maxResults: 10,
                    order: 'relevance',
                });
                result += `\n\n💬 **Top Comments**\n\n${JSON.stringify(commentsResponse.data.items, null, 2)}`;
            }
            catch (error) {
                result += '\n\n⚠️ Comments are disabled for this video';
            }
        }
        return {
            content: [
                {
                    type: 'text',
                    text: result,
                },
            ],
        };
    }
    async getChannel(args) {
        const { channel_id, username, include_statistics = true } = args;
        const params = {
            part: ['snippet', 'contentDetails'],
        };
        if (include_statistics) {
            params.part.push('statistics');
        }
        if (channel_id) {
            params.id = [channel_id];
        }
        else if (username) {
            params.forUsername = username;
        }
        else {
            return {
                content: [
                    {
                        type: 'text',
                        text: '❌ Please provide either channel_id or username',
                    },
                ],
                isError: true,
            };
        }
        const response = await this.youtube.channels.list(params);
        if (!response.data.items || response.data.items.length === 0) {
            return {
                content: [
                    {
                        type: 'text',
                        text: '❌ Channel not found',
                    },
                ],
                isError: true,
            };
        }
        const channel = response.data.items[0];
        return {
            content: [
                {
                    type: 'text',
                    text: `📺 **Channel Information**\n\n${JSON.stringify(channel, null, 2)}`,
                },
            ],
        };
    }
    async listChannelVideos(args) {
        const { channel_id, max_results = 25, order = 'date' } = args;
        const response = await this.youtube.search.list({
            part: ['snippet'],
            channelId: channel_id,
            type: ['video'],
            maxResults: Math.min(max_results, 50),
            order: order,
        });
        const videos = response.data.items || [];
        return {
            content: [
                {
                    type: 'text',
                    text: `📺 **Channel Videos**\n\nChannel ID: ${channel_id}\nFound: ${videos.length} videos\n\n${JSON.stringify(videos, null, 2)}`,
                },
            ],
        };
    }
    async getMyChannel(args) {
        const { include_analytics = false } = args;
        const response = await this.youtube.channels.list({
            part: ['snippet', 'statistics', 'contentDetails', 'brandingSettings'],
            mine: true,
        });
        if (!response.data.items || response.data.items.length === 0) {
            return {
                content: [
                    {
                        type: 'text',
                        text: '❌ No channel found for authenticated user',
                    },
                ],
                isError: true,
            };
        }
        const channel = response.data.items[0];
        return {
            content: [
                {
                    type: 'text',
                    text: `📺 **My Channel**\n\n${JSON.stringify(channel, null, 2)}`,
                },
            ],
        };
    }
    async listMyVideos(args) {
        const { max_results = 25, order = 'date' } = args;
        // First get the channel ID
        const channelResponse = await this.youtube.channels.list({
            part: ['contentDetails'],
            mine: true,
        });
        if (!channelResponse.data.items || channelResponse.data.items.length === 0) {
            return {
                content: [
                    {
                        type: 'text',
                        text: '❌ No channel found for authenticated user',
                    },
                ],
                isError: true,
            };
        }
        const uploadsPlaylistId = channelResponse.data.items[0].contentDetails.relatedPlaylists.uploads;
        // Get videos from uploads playlist
        const response = await this.youtube.playlistItems.list({
            part: ['snippet', 'contentDetails'],
            playlistId: uploadsPlaylistId,
            maxResults: Math.min(max_results, 50),
        });
        const videos = response.data.items || [];
        return {
            content: [
                {
                    type: 'text',
                    text: `🎥 **My Videos**\n\nFound: ${videos.length} videos\n\n${JSON.stringify(videos, null, 2)}`,
                },
            ],
        };
    }
    async getPlaylists(args) {
        const { channel_id, max_results = 25 } = args;
        const params = {
            part: ['snippet', 'contentDetails'],
            maxResults: Math.min(max_results, 50),
        };
        if (channel_id) {
            params.channelId = channel_id;
        }
        else {
            params.mine = true;
        }
        const response = await this.youtube.playlists.list(params);
        const playlists = response.data.items || [];
        return {
            content: [
                {
                    type: 'text',
                    text: `📑 **Playlists**\n\nFound: ${playlists.length} playlists\n\n${JSON.stringify(playlists, null, 2)}`,
                },
            ],
        };
    }
    async getPlaylistVideos(args) {
        const { playlist_id, max_results = 25 } = args;
        const response = await this.youtube.playlistItems.list({
            part: ['snippet', 'contentDetails'],
            playlistId: playlist_id,
            maxResults: Math.min(max_results, 50),
        });
        const videos = response.data.items || [];
        return {
            content: [
                {
                    type: 'text',
                    text: `📑 **Playlist Videos**\n\nPlaylist ID: ${playlist_id}\nFound: ${videos.length} videos\n\n${JSON.stringify(videos, null, 2)}`,
                },
            ],
        };
    }
    async getComments(args) {
        const { video_id, max_results = 20, order = 'relevance' } = args;
        try {
            const response = await this.youtube.commentThreads.list({
                part: ['snippet', 'replies'],
                videoId: video_id,
                maxResults: Math.min(max_results, 100),
                order: order,
            });
            const comments = response.data.items || [];
            return {
                content: [
                    {
                        type: 'text',
                        text: `💬 **Video Comments**\n\nVideo ID: ${video_id}\nFound: ${comments.length} comments\n\n${JSON.stringify(comments, null, 2)}`,
                    },
                ],
            };
        }
        catch (error) {
            return {
                content: [
                    {
                        type: 'text',
                        text: '⚠️ Comments are disabled for this video or an error occurred',
                    },
                ],
                isError: true,
            };
        }
    }
    async getTrending(args) {
        const { region_code = 'US', category_id = '0', max_results = 25 } = args;
        const params = {
            part: ['snippet', 'statistics', 'contentDetails'],
            chart: 'mostPopular',
            regionCode: region_code,
            maxResults: Math.min(max_results, 50),
        };
        if (category_id !== '0') {
            params.videoCategoryId = category_id;
        }
        const response = await this.youtube.videos.list(params);
        const videos = response.data.items || [];
        return {
            content: [
                {
                    type: 'text',
                    text: `🔥 **Trending Videos**\n\nRegion: ${region_code}\nCategory: ${category_id}\nFound: ${videos.length} videos\n\n${JSON.stringify(videos, null, 2)}`,
                },
            ],
        };
    }
    async run() {
        // Check for existing authentication on startup
        const isAuth = await this.checkAuthentication();
        if (isAuth) {
            console.error('✅ YouTube MCP Server started (authenticated)');
        }
        else {
            console.error('🔐 YouTube MCP Server started (authentication required)');
        }
        const transport = new StdioServerTransport();
        await this.server.connect(transport);
    }
}
// Start the server
const server = new LocalYouTubeMCPServer();
server.run().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
});
//# sourceMappingURL=index.js.map