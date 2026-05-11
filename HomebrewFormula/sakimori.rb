class Sakimori < Formula
  desc "Cross-platform supply-chain guard for every package manager"
  homepage "https://github.com/bokuweb/sakimori"
  license "MIT"
  version "0.32.0"

  # This formula is a per-release binary installer — we consume the
  # prebuilt tarballs that `.github/workflows/release.yml` publishes
  # to the GitHub Release. Keeps the formula tiny (no cargo build,
  # no nightly toolchain for the eBPF object) and lets users on
  # macOS benefit immediately.
  #
  # The `.github/workflows/homebrew-formula.yml` workflow rewrites
  # the URLs + sha256s on every `v*` tag push, so the only manual
  # step is the initial tap setup.

  on_macos do
    on_arm do
      url "https://github.com/bokuweb/sakimori/releases/download/v0.32.0/sakimori-aarch64-apple-darwin.tar.gz"
      sha256 "3a4d125ce4ecc9cbf3a583c2770ce071af1895958510940c1469317874829e2c"
    end
    on_intel do
      url "https://github.com/bokuweb/sakimori/releases/download/v0.32.0/sakimori-x86_64-apple-darwin.tar.gz"
      sha256 "fa38027b8058be415517b0ed4e32413fa8f7847fd7027812ae84a58c1f6784f6"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bokuweb/sakimori/releases/download/v0.32.0/sakimori-aarch64-unknown-linux-musl.tar.gz"
      sha256 "90302151f0043cac868e9588dd34acb168e75c3df94bd28a8b7c7e0e24f79b21"
    end
    on_intel do
      url "https://github.com/bokuweb/sakimori/releases/download/v0.32.0/sakimori-x86_64-unknown-linux-musl.tar.gz"
      sha256 "cfe872eca1cd0331ba9e45dfc1cae16dd526609e2ad8e827b8b5e0047eed134e"
    end
  end

  def install
    bin.install "sakimori"
    # Linux tarball also ships the eBPF object — only useful for
    # `sakimori run` supervised mode. Install it next to the binary
    # so the default `SAKIMORI_BPF_OBJ` search path finds it.
    if OS.linux?
      (libexec/"bpf").install "sakimori.bpf.o" if File.exist?("sakimori.bpf.o")
    end
  end

  def caveats
    <<~EOS
      sakimori is installed. Desktop quick start (three commands):

        sakimori proxy install-ca        # trust the proxy's root CA
        sakimori proxy install-daemon    # run the proxy in the background
        sakimori install-gate install    # route your shell through it

      Open a new shell, then `npm install` / `cargo add` / `pip install` will
      silently fall back to versions older than --min-age (default 7d).

      Verify the install:

        sakimori doctor

      #{OS.linux? ? "eBPF supervised-run mode (`sakimori run`) needs the bpf object at:\n  #{libexec}/bpf/sakimori.bpf.o\nExport SAKIMORI_BPF_OBJ=$(brew --prefix)/opt/sakimori/libexec/bpf/sakimori.bpf.o\nbefore running `sakimori run`." : ""}
    EOS
  end

  test do
    # Smoke the binary starts and reports its version.
    assert_match version.to_s, shell_output("#{bin}/sakimori --version")
    # Policy parser exits cleanly on a minimal document.
    (testpath/"policy.yml").write <<~YAML
      mode: audit
      network:
        default: allow
      file:
        default: allow
    YAML
    system "#{bin}/sakimori", "check-policy", "-p", testpath/"policy.yml"
  end
end
