# Why Shekyl Comes in Two Parts — and Why You Need Both

Shekyl is made of two pieces that work together: a **wallet** and a **daemon** (the daemon's program is named `shekyld`). Depending on how you set things up, you may have installed them together or separately — but either way, both are present and both are necessary.

A lot of people expect a single app that does everything, so seeing two pieces is confusing. Some assume one of them is leftover clutter and remove it. Please don't: they're two halves of one tool, and deleting either one breaks the other. Here's what each does, in plain terms, and why Shekyl is built this way on purpose.

## The short version

The **daemon** is your connection to the Shekyl network and your own verified copy of its public ledger. The **wallet** holds your private keys and is the only part that knows which money is yours and can spend it. The wallet reads the ledger through the daemon, and hands its signed payments back to the daemon to broadcast.

One piece handles the shared, public side. The other handles your private, personal side. Neither can do the other's job.

## A way to picture it: a public ledger and a private key

Imagine a town where every payment ever made is written into one enormous public ledger. Anyone can read it, but nobody can secretly forge or alter an entry — because thousands of residents each keep their own complete, independently-checked copy and constantly compare notes. That shared, tamper-proof record is the blockchain.

**The daemon is your copy of that ledger, plus your membership in the network of people keeping copies.** It downloads each new page as it's written, checks that every entry obeys the rules (no counterfeiting, no spending the same coin twice), and keeps your copy honest and current. It's how you take part in the shared truth without having to trust anyone else's word for what happened.

But Shekyl's ledger is written to protect privacy: the entries are deliberately anonymous, so you can't just skim the pages and spot "that one's mine." That's where your keys come in.

**The wallet holds your private keys** — the secret that can recognize which of those anonymous entries belong to you, and the only thing that can authorize new ones. Using the ledger your daemon provides, the wallet finds your funds, adds up your balance, and shows your history. When you send Shekyl, the wallet writes the new entry, signs it with your key, and passes it to the daemon to announce to the rest of the network.

So the daemon deals with everyone's public record; the wallet deals with your private money. The daemon never sees your keys and literally cannot tell which coins are yours or move them. The wallet never has to download or police the entire network — it leans on the daemon for that.

## At a glance

| The daemon (`shekyld`) | The wallet |
|---|---|
| Talks to the Shekyl network (other computers running Shekyl) | Talks only to a daemon — usually yours |
| Downloads and stores the full blockchain | Stores your keys, addresses, and history |
| Checks that every block and transaction follows the rules | Finds which funds are yours and totals your balance |
| Broadcasts transactions to the world | Creates and signs your transactions |
| Knows nothing about who you are | Knows everything about your money |
| Holds no keys and controls no funds | Holds your keys — this is your money |

## Why two parts? It's intentional, not extra baggage

This split buys three things that matter a great deal for a privacy-focused currency.

**Security through separation.** Your keys — the only thing that can spend your money — live solely in the wallet and never touch the part of the software that's exposed to the open internet. The daemon, which is constantly talking to strangers on the network, has nothing worth stealing: no keys, no ability to identify or move your funds. If one piece is going to take on risk by facing the outside world, you want it to be the piece that holds none of your secrets.

**Privacy through self-reliance.** When you run your own daemon, you verify the ledger yourself and you don't have to tell anyone else what you're looking for. Your wallet quietly asks your own daemon "is any of this mine?" — a question that never leaves your control. Leaning on someone else's computer for that view would leak hints about your activity. For a coin built around privacy, being able to stand on your own is the whole point.

**Flexibility.** Because the daemon is independent, it can keep syncing in the background, run on a spare machine or a home server, and serve more than one wallet. The wallet stays light and personal. You can arrange the two pieces to fit how you actually use Shekyl.

## "Can I just delete one of them?"

No — and here's exactly what happens if you do.

**Delete the daemon** (and don't point your wallet at someone else's), and the wallet has no ledger to read and no way to reach the network. It can't show your balance, can't update, and can't send anything. Your money is still safe out on the blockchain — but your wallet has gone blind and mute.

**Delete the wallet**, and you've removed the only key that can find and spend your funds. The daemon keeps humming along with everyone's ledger, but your coins stay out of reach without your keys. (This is why your recovery seed matters: with it, you can reinstall the wallet and get everything back. Without the wallet *and* without the seed, there's no way in.)

It's like a lock and its key. A lock with no key is useless; a key with no lock opens nothing. Shekyl needs both halves to work.

## "Do I have to run the daemon myself?"

The wallet always needs a daemon to reach the network — but it doesn't have to be one on your own computer. You can run your own, which is the most private and self-reliant option, or connect your wallet to a daemon someone else runs, which is more convenient but means trusting a third party for your view of the chain. Either way the daemon is doing the same job; the only question is whose machine it runs on. If privacy is your priority — and with Shekyl, it usually is — running your own is the way to go.

## The takeaway

Two programs, one tool. The daemon is your trusted, verified window onto the Shekyl network. The wallet is your private key to your own money. Keep both, and they quietly do their separate jobs so you don't have to think about the seam between them.
