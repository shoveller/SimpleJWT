import {getRefreshToken, getAccessToken, verifyJwt,} from "./main.ts";
import { assertSnapshot } from "@std/testing/snapshot";
import { assertEquals } from '@std/assert'

Deno.test("액세스 토큰을 생성할 수 있다.", async (ctx) => {
    const jwt = await getAccessToken("김땡탄");
    await assertSnapshot(ctx, jwt)
})

Deno.test("리프레시 토큰을 생성할 수 있다.", async (ctx) => {
    const jwt = await getRefreshToken("김땡탄");
    await assertSnapshot(ctx, jwt)
})

Deno.test("액세스 토큰을 검증할 수 있다.", async (ctx) => {
    const jwt = await getAccessToken("김땡탄");
    const payload = await verifyJwt(jwt)
    await assertSnapshot(ctx, payload);

    const fakePayload = await verifyJwt('')
    assertEquals(fakePayload, null);
    await assertSnapshot(ctx, fakePayload);
})
