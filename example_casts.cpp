//
// Created by ray on 6/11/20.
//
#include <iostream>

using namespace std;

int main()
{
  int x = 0;
  std::cout<<x<<std::endl;

  // const reference
  const int& i = x;
  int& j = const_cast<int&>(i);
  j = 1;

  // Outputs 1
  std::cout<<x<<std::endl;

  // const pointer
  const int* k = &j;
  int* l = const_cast<int*>(k);
  *l = 2;

  // Outputs 2
  std::cout<<x<<std::endl;

  // --- Using c-style ---
  // Outputs 3
  int& a = (int&) i;
  a = 3;
  std::cout<<x<<std::endl;

  // Outputs 4
  int* b = (int*) k;
  *b = 4;
  std::cout<<x<<std::endl;

  return 0;
}