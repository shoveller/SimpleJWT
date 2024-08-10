import {create, getNumericDate, verify} from "djwt";

const alg = "HS512";
const key = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-512" },
    true,
    ["sign", "verify"],
);

type PayloadType = {
    iss: string;
    sub: string;
    exp: number;
};

// 토큰을 생성한다
export async function generateJwt(payload: PayloadType) {
    return await create({ alg, typ: "JWT" }, payload, key);
}

export async function getAccessToken(username: string) {
    return await generateJwt({
        iss: "your-app",
        sub: username,
        exp: getNumericDate(60 * 60), // 1시간 유효
    });
}

// 리프레시 토큰 생성. 리프레시 토큰은 유효기간이 길다. 나머지는 액세스 토큰과 같다
export async function getRefreshToken(username: string) {
    return await generateJwt({
        iss: "your-app",
        sub: username,
        exp: getNumericDate(60 * 60 * 24 * 7), // 1주일 유효
    });
}

// JWT 토큰 검증
export async function verifyJwt(token: string) {
    try {
        return await verify(token, key);
    } catch (error) {
        console.error("Invalid JWT:", error);
        return null;
    }
}

// 로그인
async function login(req: Request) {
    const { username } = await req.json();
    if (!username) {
        return new Response("Username is required", { status: 400 });
    }

    // Access Token과 Refresh Token 생성
    const accessToken = await getAccessToken(username);
    const refreshToken = await getRefreshToken(username);

    return new Response(JSON.stringify({ accessToken, refreshToken }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
    });
}

// 보호된 경로 핸들러
async function resource(req: Request) {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        // 토큰이 없으면 인증 실패
        return new Response("Unauthorized", { status: 401 });
    }

    const token = authHeader.substring(7);
    const payload = await verifyJwt(token);
    if (payload) {
        return new Response(`Hello, ${payload.sub}!`, { status: 200 });
    }

    // 토큰이 검증을 통과하지 못하면 토큰 실패
    return new Response("Invalid token", { status: 401 });
}

// 토큰 갱신 핸들러 (리프레시 토큰 사용)
async function tokenRefresh(req: Request) {
    const { refreshToken } = await req.json();
    // 리프레시 토큰이 없으면 400 처리
    if (!refreshToken) {
        return new Response("Refresh token is required", { status: 400 });
    }

    // 리프레시 토큰 검증에 실패하면 401 처리
    const payload = await verifyJwt(refreshToken);
    if (!payload) {
        return new Response("Invalid refresh token", { status: 401 });
    }

    // 토큰 검증에 성공하면 새로운 토큰 발급
    const accessToken = await getAccessToken(payload.sub!);
    return new Response(JSON.stringify({ accessToken }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
    });
}

if (import.meta.main) {
    Deno.serve((req) => {
        const url = new URL(req.url);
        if (url.pathname === "/") {
            return resource(req);
        }
        if (url.pathname === "/login" && req.method === "POST") {
            return login(req);
        }
        if (url.pathname === "/refresh" && req.method === "POST") {
            return tokenRefresh(req);
        }

        return new Response("404", { status: 404 });
    });
}
