#!/usr/bin/env bats

@test "reject because privileged container" {
  run kwctl run annotated-policy.wasm -r test_data/privileged_container.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*Privileged container is not allowed*') -ne 0 ]

}

@test "accept" {
  run kwctl run annotated-policy.wasm -r test_data/no_privileged_containers.json
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}


@test "reject deployment because privileged container" {
  run kwctl run annotated-policy.wasm -r test_data/deployment_with_privileged_containers.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*Privileged container is not allowed*') -ne 0 ]
}

@test "reject statefulset because privileged container" {
  run kwctl run annotated-policy.wasm -r test_data/statefulset_with_privileged_container.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*Privileged container is not allowed*') -ne 0 ]
}

@test "accept privileged init container when required" {
  run kwctl run annotated-policy.wasm -r test_data/privileged_init_container.json --settings-path test_data/settings_skip_init_and_ephemeral_containers.json
  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}

@test "accept privileged ephemeral container when required" {
  run kwctl run annotated-policy.wasm -r test_data/privileged_ephemeral_container.json --settings-path test_data/settings_skip_init_and_ephemeral_containers.json
  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
