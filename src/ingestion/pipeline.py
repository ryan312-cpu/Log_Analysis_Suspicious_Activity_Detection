from src.ingestion.log_collector import LogCollector


def run_ingestion():

    collector = LogCollector(
        "data/raw"
    )

    files = collector.discover_log_files()

    print("=" * 60)
    print("LOG INGESTION PIPELINE")
    print("=" * 60)

    print(f"Discovered log files: {len(files)}")
    print()

    total_lines = 0

    for file_path in files:

        lines = collector.collect()[
            str(file_path)
        ]

        line_count = len(lines)

        total_lines += line_count

        print(
            f"[INGESTED] "
            f"{file_path} "
            f"({line_count} lines)"
        )

    print()
    print("-" * 60)
    print(
        f"Total ingested log lines: "
        f"{total_lines}"
    )
    print("-" * 60)


if __name__ == "__main__":
    run_ingestion()
