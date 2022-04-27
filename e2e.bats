#!/usr/bin/env bats

@test "reject because privileged container" {
  run kwctl run annotated-policy.wasm -r assembly/__tests__/fixtures/privileged_container.json

  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request rejected
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*false') -ne 0 ]
  [ $(expr "$output" : '.*Privileged containers are not allowed*') -ne 0 ]

}

@test "accept" {
  run kwctl run annotated-policy.wasm -r assembly/__tests__/fixtures/no_privileged_containers.json
  # this prints the output when one the checks below fails
  echo "output = ${output}"

  # request accepted
  [ "$status" -eq 0 ]
  [ $(expr "$output" : '.*allowed.*true') -ne 0 ]
}
