import "./App.css"
import { useState } from "react";
import SearchBar from "./components/SearchBar";
import ProductList from "./components/ProductList"
const App = () => {
  const[input, setInput] = useState('')

  const handleInputChange = (event) => {
    console.log(event.target.value)
    setInput(event.target.value)
  }

  const handleSearchClick = (event) => {
    event.preventDefault()
    console.log('button clicked', input)
  }

  return (
    <div>
      <SearchBar input = {input}
                handleInputChange = {handleInputChange}
                handleSearchClick={handleSearchClick} 
      />
      <ProductList />
    </div>
  )
}

export default App
