import { assertEquals } from "jsr:@std/assert";
import decodeBase32 from "base32-decode";

Deno.test("base32 decoding", () => {
  // Checks that decoding Crockford base32 with some easy-to-mix-up characters swapped still works.
  assertEquals(
    decodeBase32(
      "pxdefp036gx09n8m8mex0bsrg1pgx4498sqvsv8kf5ae4253yga0",
      "Crockford"
    ),
    decodeBase32(
      "pXdefp036gx09n8m8mex0bsrglpgx4498Sqvsv8kf5ae4253ygaO",
      "Crockford"
    )
  );
});
