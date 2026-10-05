import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  CheckCircle2,
  ChevronRight,
  ShieldQuestion,
  XCircle,
} from "lucide-react";
import SiteHeader from "@/components/SiteHeader";

type Question = {
  prompt: string;
  options: string[];
  answer: number;
  explanation: string;
};
const questions: Question[] = [
  {
    prompt: "Which address is most suspicious?",
    options: [
      "https://accounts.google.com",
      "https://google.com",
      "https://google-login.verify-account.example/",
      "https://support.google.com",
    ],
    answer: 2,
    explanation:
      "The real destination is example.com; brand words in a subdomain do not make it Google.",
  },
  {
    prompt:
      "A message says your account closes in 10 minutes unless you act. What is the safest first step?",
    options: [
      "Click immediately",
      "Reply with your password",
      "Pause and verify through the official app or website",
      "Forward it to friends",
    ],
    answer: 2,
    explanation:
      "Urgency is commonly used to stop people from checking a message independently.",
  },
  {
    prompt:
      "Which login detail should never be shared through a link in an unexpected message?",
    options: [
      "Your password or one-time code",
      "The weather",
      "A public company name",
      "A website's colour",
    ],
    answer: 0,
    explanation:
      "Passwords and one-time codes can give an attacker direct access to an account.",
  },
  {
    prompt: "What should you check before entering mobile-money details?",
    options: [
      "Whether the page has many animations",
      "The exact domain and the official support channel",
      "Whether the offer uses emojis",
      "How urgent the message sounds",
    ],
    answer: 1,
    explanation:
      "Confirm the exact destination and use a trusted channel rather than a link supplied unexpectedly.",
  },
  {
    prompt:
      "A prize page asks for a small payment to release winnings. What is the strongest warning sign?",
    options: [
      "It has a logo",
      "It asks for payment or sensitive details before a prize",
      "It loads quickly",
      "It uses a green button",
    ],
    answer: 1,
    explanation: "Advance-fee requests are a common giveaway scam pattern.",
  },
];

export default function Quiz() {
  const [index, setIndex] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const [score, setScore] = useState(0);
  const finished = index >= questions.length;
  const current = questions[index];
  const choose = (choice: number) => {
    if (selected !== null) return;
    setSelected(choice);
    if (choice === current.answer) setScore(value => value + 1);
  };
  const next = () => {
    setIndex(value => value + 1);
    setSelected(null);
  };
  const restart = () => {
    setIndex(0);
    setSelected(null);
    setScore(0);
  };
  const message =
    score === 5
      ? "Excellent instincts. Keep verifying before you click."
      : score >= 3
        ? "Good awareness. Slow down on urgent requests and check the destination."
        : "Keep practising. Pause, inspect the address, and verify through a trusted channel.";
  return (
    <div className="min-h-screen bg-[#081018] text-[#edf5f2]">
      <SiteHeader />
      <main className="relative z-10 mx-auto max-w-3xl px-6 pb-20 pt-10 lg:px-10">
        <div className="mb-8">
          <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#8df0b8]">
            Phishing awareness
          </p>
          <h1 className="mt-3 text-4xl font-semibold tracking-tight text-[#f4fbf8] sm:text-5xl">
            Test yourself
          </h1>
          <p className="mt-4 leading-7 text-[#c1cfcb]">
            Five quick questions about suspicious links, urgent messages, and
            fake offers. No sign-in required.
          </p>
        </div>
        {finished ? (
          <Card className="border-[#8df0b8]/20 bg-[#101b22]/90">
            <CardContent className="p-8 text-center sm:p-12">
              <ShieldQuestion className="mx-auto h-12 w-12 text-[#8df0b8]" />
              <p className="mt-5 font-mono text-[11px] uppercase tracking-[0.18em] text-[#9fb0ac]">
                Your result
              </p>
              <p className="mt-2 text-6xl font-semibold text-[#8df0b8]">
                {score}
                <span className="text-2xl text-[#9fb0ac]">/5</span>
              </p>
              <h2 className="mt-5 text-xl font-semibold text-[#f4fbf8]">
                {message}
              </h2>
              <Button
                onClick={restart}
                className="mt-7 bg-[#8df0b8] font-semibold text-[#09130f] hover:bg-[#b0f7cd]"
              >
                Try again
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-white/10 bg-[#101b22]/90">
            <CardHeader>
              <div className="flex items-center justify-between gap-3">
                <CardTitle className="text-xl text-[#f4fbf8]">
                  Question {index + 1} of {questions.length}
                </CardTitle>
                <span className="font-mono text-xs text-[#9fb0ac]">
                  {score} correct
                </span>
              </div>
              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-white/10">
                <div
                  className="h-full rounded-full bg-[#8df0b8] transition-all"
                  style={{
                    width: `${((index + 1) / questions.length) * 100}%`,
                  }}
                />
              </div>
            </CardHeader>
            <CardContent>
              <h2 className="text-xl font-semibold leading-8 text-[#f4fbf8]">
                {current.prompt}
              </h2>
              <div className="mt-6 grid gap-3">
                {current.options.map((option, choice) => {
                  const answered = selected !== null;
                  const correct = choice === current.answer;
                  const picked = choice === selected;
                  return (
                    <button
                      key={option}
                      type="button"
                      onClick={() => choose(choice)}
                      className={`flex min-w-0 items-start gap-3 rounded-xl border p-4 text-left text-sm transition ${answered && correct ? "border-[#6ee7a5]/50 bg-[#6ee7a5]/10 text-[#9bf3c1]" : answered && picked ? "border-[#ff6b5f]/40 bg-[#ff6b5f]/10 text-[#ffb4ab]" : "border-white/10 bg-[#081018]/55 text-[#c1cfcb] hover:border-[#8df0b8]/40 hover:text-[#f4fbf8]"}`}
                    >
                      {answered && correct ? (
                        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
                      ) : answered && picked ? (
                        <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
                      ) : (
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-current text-[10px]">
                          {String.fromCharCode(65 + choice)}
                        </span>
                      )}
                      <span className="phishguard-wrap">{option}</span>
                    </button>
                  );
                })}
              </div>
              {selected !== null && (
                <div
                  className={`mt-5 rounded-xl border p-4 text-sm leading-6 ${selected === current.answer ? "border-[#6ee7a5]/20 bg-[#6ee7a5]/[0.08] text-[#9bf3c1]" : "border-[#f3b74f]/20 bg-[#f3b74f]/[0.08] text-[#ffd28a]"}`}
                >
                  <strong>
                    {selected === current.answer ? "Correct. " : "Not quite. "}
                  </strong>
                  {current.explanation}
                </div>
              )}
              {selected !== null && (
                <Button
                  onClick={next}
                  className="mt-6 w-full bg-[#8df0b8] font-semibold text-[#09130f] hover:bg-[#b0f7cd]"
                >
                  {index === questions.length - 1
                    ? "See my score"
                    : "Next question"}
                  <ChevronRight className="ml-2 h-4 w-4" />
                </Button>
              )}
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}
