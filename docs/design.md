# Design and limitations
Starting a seat assigns a random session cookie. The local server maps that cookie to a numeric participant and uses a fixed synthetic event and challenge ID. It intentionally serves a supervisor note to an authenticated analyst who changes the object identifier. All records are fictional.

The embedded flag service serializes the participant, event, challenge and key identifier and computes a truncated HMAC-SHA256 tag with a fresh process key. Verification compares tags in constant time. Copying the literal flag to another seat fails. Sharing the solution technique still works.

This reviewer build pairs the extracted flag service with a new Node.js adaptation of the synthetic exercise. It has no public hosting, scoreboard, persistent accounts or production orchestration. Stop the server to discard the sessions and key.
