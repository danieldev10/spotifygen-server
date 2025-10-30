import axios from "axios";

export async function analyzePromptWithMistral(prompt) {
    try {
        const response = await axios.post(
            "https://api.mistral.ai/v1/chat/completions",
            {
                model: "mistral-small-latest",
                messages: [
                    {
                        role: "system",
                        content: `You are a music assistant.
Always reply ONLY with valid JSON in this format:
{
  "title": "string (max 50 chars)",
  "genres": ["genre1","genre2"],
  "artists": ["artist1","artist2"]
}`
                    },
                    { role: "user", content: prompt }
                ],
                temperature: 0.7
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.MISTRAL_API_KEY}`,
                    "Content-Type": "application/json"
                }
            }
        );

        let text = response.data.choices[0].message.content.trim();

        if (text.startsWith("```")) {
            text = text.replace(/```json|```/g, "").trim();
        }

        return JSON.parse(text);
    } catch (error) {
        console.error("Error with Mistral AI:", error.response?.data || error.message);
        throw new Error("Mistral AI analysis failed");
    }
}
