add_executable(test main_test.c)

target_link_libraries(test PRIVATE parser)
