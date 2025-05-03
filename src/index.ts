/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */




const EGG_REPOS: Record<string, string> =
{
	"ptero-eggs/game-eggs": "Game Eggs",
	"ptero-eggs/generic-eggs": "Generic Eggs",
	"ptero-eggs/application-eggs": "Application Eggs",
	"ptero-eggs/yolks": "Yolks",
};

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const WEBHOOK_SECRET = env.WEBHOOK_SECRET;
		const DISCORD_WEBHOOK_URL = env.DISCORD_WEBHOOK_URL;


		try {

			const rawBody = await request.text();


			// Check for the GitHub webhook secret
			const isValid = await verifyGitHubWebhook(rawBody, request.headers.get("X-Hub-Signature-256"), WEBHOOK_SECRET);
			if (!isValid) {
				return new Response("Invalid webhook signature", { status: 401 });
			}


			let payload: any;
			try{
				payload = JSON.parse(rawBody);
			} catch (e) {
				return new Response(`Invalid JSON payload: ${(e as Error).message}`, { status: 400 });
			}


			// Drop requests for non-main branch
			if (payload.ref !== 'refs/heads/main') {
				return new Response('Branch is not main', { status: 200 });
			}

			// Drop requests for non-push events
			if (request.headers.get("X-GitHub-Event") !== "push") {
				return new Response("Not a push event", { status: 200 });
			}


			// Drop requests for repos not in the list
			if (!Object.hasOwn(EGG_REPOS, payload.repository.full_name.toLowerCase())) {
				return new Response(`Repo ${payload.repository.full_name} is not in watch list`, { status: 200 });
			}



			const { repository, commits } = payload;

			// Build the Discord message
			const commitMessages = commits
				.map((commit: { id: string; message: any; url: string }) => {
					const firstLine = commit.message.split("\n")[0];
					return `- [[${commit.id.substring(0, 7)}](<${commit.url}>)] ${firstLine}`;
				})
				.join("\n");

			const messageContent = {
				username: "GitHub",
				avatar_url: "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
				content: `New commits to **[${EGG_REPOS[repository.full_name.toLowerCase()]}](${repository.url})** repository\n${commitMessages}`,
				allowed_mentions: {
					parse: [],
				},
			};

			// Send the message to Discord
			const discordResponse = await fetch(DISCORD_WEBHOOK_URL, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(messageContent),
			});

			if (!discordResponse.ok) {
				throw new Error(`Discord webhook failed with status ${discordResponse.status} - ${await discordResponse.text()}`);
			}

			return new Response("Notification sent to Discord.", { status: 200 });
		} catch (e : any) {
			return new Response(`Error: ${e.message}`, { status: 500 });
		}


	},
} satisfies ExportedHandler<Env>;



async function createHmac(key: string, message: string): Promise<string> {
	const encoder = new TextEncoder();
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		encoder.encode(key),
		{ name: "HMAC", hash: { name: "SHA-256" } },
		false,
		["sign"]
	);

	const signature = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));

	// Convert ArrayBuffer to Hex String
	const signatureArray = Array.from(new Uint8Array(signature));
	return signatureArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyGitHubWebhook(rawBody: string, signature: string | null, secret: string): Promise<boolean> {
	// Get the GitHub signature header

	if (!signature) {
		return false; // Signature missing
	}

	// Extract the hash from the header (it starts with "sha256=")
	const expectedSignature = signature.replace("sha256=", "");

	// Generate the HMAC using the secret and the raw body
	const generatedSignature = await createHmac(secret, rawBody);

	// Perform a timing-safe comparison
	const encoder = new TextEncoder();
	const generatedSignatureBytes = encoder.encode(generatedSignature);
	const expectedSignatureBytes = encoder.encode(expectedSignature);

	if (generatedSignatureBytes.length !== expectedSignatureBytes.length) {
		return false;
	}

	let isEqual = true;
	for (let i = 0; i < generatedSignatureBytes.length; i++) {
		if (generatedSignatureBytes[i] !== expectedSignatureBytes[i]) {
			isEqual = false;
		}
	}

	return isEqual;
}
